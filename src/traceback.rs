//! Python traceback parser for structured diagnostic output.
//!
//! Converts raw Python stderr into machine-readable `ParsedTraceback` values
//! with stable `E_*` error codes and structured `next_action` hints.

use serde::{Deserialize, Serialize};

/// A structured next action that an agent can call directly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NextAction {
    /// MCP tool name to invoke.
    pub tool: String,
    /// Arguments to pass to the tool.
    pub args: serde_json::Value,
}

/// The innermost frame from a Python traceback.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TracebackLocation {
    /// Project-root-relative file path (falls back to raw path).
    pub file: String,
    /// Line number where the exception occurred.
    pub line: u32,
    /// Function or scope name.
    pub function: String,
}

/// Parsed representation of a Python exception.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParsedTraceback {
    /// Stable `E_*` error code (e.g. `E_RUNTIME_MODULE_NOT_FOUND`).
    pub code: String,
    /// Python exception class name (e.g. `ModuleNotFoundError`).
    pub exception_type: String,
    /// Exception message text.
    pub message: String,
    /// Location of the innermost traceback frame.
    pub location: Option<TracebackLocation>,
    /// Structured action an agent can take to resolve the error.
    pub next_action: Option<NextAction>,
}

/// Parse raw Python stderr into a `ParsedTraceback`.
///
/// Returns `None` if the text does not look like a Python exception.
pub fn parse(stderr: &str) -> Option<ParsedTraceback> {
    // Must contain the standard Python traceback header or a bare exception line
    let has_traceback_header = stderr.contains("Traceback (most recent call last):");
    let has_exception_line = stderr.lines().any(looks_like_exception_line);

    if !has_traceback_header && !has_exception_line {
        return None;
    }

    let location = extract_innermost_frame(stderr);
    let (exception_type, message) = extract_exception(stderr)?;
    let code = map_exception_to_code(&exception_type, &message);
    let next_action = build_next_action(&exception_type, &message);

    Some(ParsedTraceback {
        code,
        exception_type,
        message,
        location,
        next_action,
    })
}

fn looks_like_exception_line(line: &str) -> bool {
    // Bare exception lines: "ExceptionType: message" or "ExceptionType" alone
    // Must start with an uppercase letter and not have leading whitespace
    let trimmed = line.trim_start();
    if trimmed != line {
        return false; // indented — part of a frame, not the exception line
    }
    if let Some((candidate, _)) = line.split_once(':') {
        is_exception_type_candidate(candidate.trim())
    } else {
        is_exception_type_candidate(line.trim())
    }
}

fn is_exception_type_candidate(candidate: &str) -> bool {
    // Exception class names: only word characters, possibly dotted (e.g. pkg.MyError)
    !candidate.is_empty()
        && candidate
            .chars()
            .next()
            .map(|c| c.is_ascii_uppercase())
            .unwrap_or(false)
        && candidate
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
}

/// Extract the innermost (last) `File "...", line N[, in <func>]` frame.
///
/// SyntaxError frames omit the `, in <func>` part; we handle both forms.
fn extract_innermost_frame(stderr: &str) -> Option<TracebackLocation> {
    let mut last_file: Option<String> = None;
    let mut last_line_no: Option<u32> = None;
    let mut last_func: Option<String> = None;

    for line in stderr.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("File \"")
            && let Some((path_part, rest2)) = rest.split_once("\", line ")
        {
            let path = path_part.to_string();
            if let Some((line_str, func_part)) = rest2.split_once(", in ") {
                // Standard form: File "path", line N, in func
                if let Ok(ln) = line_str.trim().parse::<u32>() {
                    last_file = Some(path);
                    last_line_no = Some(ln);
                    last_func = Some(func_part.trim().to_string());
                }
            } else if let Ok(ln) = rest2
                .trim()
                .trim_end_matches(|c: char| !c.is_ascii_digit())
                .trim()
                .parse::<u32>()
            {
                // SyntaxError form: File "path", line N (no ", in func" suffix)
                last_file = Some(path);
                last_line_no = Some(ln);
                last_func = None;
            }
        }
    }

    match (last_file, last_line_no) {
        (Some(file), Some(line)) => Some(TracebackLocation {
            file: make_relative(file),
            line,
            function: last_func.unwrap_or_else(|| "<module>".to_string()),
        }),
        _ => None,
    }
}

/// Strip leading "./" or absolute prefix to keep paths project-relative.
fn make_relative(path: String) -> String {
    // Remove "./" prefix
    if let Some(stripped) = path.strip_prefix("./") {
        return stripped.to_string();
    }
    let path_ref = std::path::Path::new(&path);
    if path_ref.is_absolute()
        && let Ok(cwd) = std::env::current_dir()
    {
        if let Ok(relative) = path_ref.strip_prefix(&cwd) {
            return relative.to_string_lossy().to_string();
        }
        if let (Ok(canonical_path), Ok(canonical_cwd)) =
            (path_ref.canonicalize(), cwd.canonicalize())
            && let Ok(relative) = canonical_path.strip_prefix(canonical_cwd)
        {
            return relative.to_string_lossy().to_string();
        }
    }
    path
}

/// Extract the exception type and message from the last exception line in stderr.
fn extract_exception(stderr: &str) -> Option<(String, String)> {
    // Walk lines in reverse to find the final "ExceptionType: message" line
    // Skip lines that start with whitespace (they are frame content)
    for line in stderr.lines().rev() {
        if line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }
        if line == "Traceback (most recent call last):" {
            continue;
        }
        if let Some((exc_type, msg)) = line.split_once(':') {
            let exc_type = exc_type.trim();
            if is_exception_type_candidate(exc_type) {
                return Some((exc_type.to_string(), msg.trim().to_string()));
            }
        } else {
            let exc_type = line.trim();
            if is_exception_type_candidate(exc_type) {
                return Some((exc_type.to_string(), String::new()));
            }
        }
    }
    None
}

/// Map a Python exception type (and optionally message) to a stable `E_*` code.
fn map_exception_to_code(exception_type: &str, message: &str) -> String {
    // Normalise dotted names: take only the last component
    let base = exception_type.rsplit('.').next().unwrap_or(exception_type);

    match base {
        "ModuleNotFoundError" => "E_RUNTIME_MODULE_NOT_FOUND".to_string(),
        "ImportError" => {
            if message.contains("No module named") {
                "E_RUNTIME_MODULE_NOT_FOUND".to_string()
            } else {
                "E_RUNTIME_IMPORT_ERROR".to_string()
            }
        }
        "SyntaxError" | "IndentationError" | "TabError" => "E_RUNTIME_SYNTAX_ERROR".to_string(),
        "TypeError" => "E_RUNTIME_TYPE_ERROR".to_string(),
        "AttributeError" => "E_RUNTIME_ATTRIBUTE_ERROR".to_string(),
        "PermissionError" => "E_RUNTIME_PERMISSION_DENIED".to_string(),
        "FileNotFoundError" => "E_RUNTIME_FILE_NOT_FOUND".to_string(),
        "ValueError" => "E_RUNTIME_VALUE_ERROR".to_string(),
        "KeyError" => "E_RUNTIME_KEY_ERROR".to_string(),
        "IndexError" => "E_RUNTIME_INDEX_ERROR".to_string(),
        "NameError" | "UnboundLocalError" => "E_RUNTIME_NAME_ERROR".to_string(),
        "RecursionError" => "E_RUNTIME_RECURSION_ERROR".to_string(),
        "MemoryError" => "E_RUNTIME_MEMORY_ERROR".to_string(),
        "TimeoutError" | "asyncio.TimeoutError" => "E_RUNTIME_TIMEOUT".to_string(),
        "SystemExit" => "E_RUNTIME_EXIT_NONZERO".to_string(),
        "KeyboardInterrupt" => "E_RUNTIME_INTERRUPTED".to_string(),
        "AssertionError" => "E_RUNTIME_ASSERTION_ERROR".to_string(),
        "OSError" | "IOError" => "E_RUNTIME_IO_ERROR".to_string(),
        "ConnectionError"
        | "ConnectionRefusedError"
        | "ConnectionResetError"
        | "BrokenPipeError" => "E_RUNTIME_CONNECTION_ERROR".to_string(),
        _ => "E_RUNTIME_UNKNOWN".to_string(),
    }
}

/// Build a structured `NextAction` when we can determine the right remediation tool.
fn build_next_action(exception_type: &str, message: &str) -> Option<NextAction> {
    let base = exception_type.rsplit('.').next().unwrap_or(exception_type);

    if matches!(base, "ModuleNotFoundError")
        || (base == "ImportError" && message.contains("No module named"))
    {
        // Extract package name from "No module named 'foo'" or "No module named foo"
        let package = extract_module_name(message)?;
        return Some(NextAction {
            tool: "pybun_add".to_string(),
            args: serde_json::json!({ "package": package }),
        });
    }

    None
}

/// Extract the module/package name from a "No module named '...'" message.
fn extract_module_name(message: &str) -> Option<String> {
    // Try quoted form: No module named 'foo.bar' → "foo"
    if let Some(after) = message.find("No module named '") {
        let start = after + "No module named '".len();
        let rest = &message[start..];
        let end = rest.find('\'')?;
        let full_name = &rest[..end];
        // Return only top-level package name
        let top = full_name.split('.').next().unwrap_or(full_name);
        if !top.is_empty() {
            return Some(top.to_string());
        }
    }
    // Try unquoted form: No module named foo
    if let Some(after) = message.find("No module named ") {
        let rest = message[after + "No module named ".len()..].trim();
        let top = rest.split(['.', ' ']).next().unwrap_or(rest);
        if !top.is_empty() {
            return Some(top.to_string());
        }
    }
    None
}

// ─── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const MODULE_NOT_FOUND: &str = r#"Traceback (most recent call last):
  File "app.py", line 3, in <module>
    import numpy
ModuleNotFoundError: No module named 'numpy'"#;

    const SYNTAX_ERROR: &str = r#"  File "app.py", line 5
    print("hello"
         ^
SyntaxError: '(' was never closed"#;

    const TYPE_ERROR: &str = r#"Traceback (most recent call last):
  File "script.py", line 10, in process
    result = value + 1
TypeError: unsupported operand type(s) for +: 'NoneType' and 'int'"#;

    const ATTRIBUTE_ERROR: &str = r#"Traceback (most recent call last):
  File "main.py", line 7, in run
    obj.foo()
AttributeError: 'NoneType' object has no attribute 'foo'"#;

    const NAME_ERROR: &str = r#"Traceback (most recent call last):
  File "run.py", line 2, in <module>
    print(undefined_var)
NameError: name 'undefined_var' is not defined"#;

    const FILE_NOT_FOUND: &str = r#"Traceback (most recent call last):
  File "reader.py", line 4, in load
    open("missing.txt")
FileNotFoundError: [Errno 2] No such file or directory: 'missing.txt'"#;

    const SUBPACKAGE_MODULE_NOT_FOUND: &str = r#"Traceback (most recent call last):
  File "app.py", line 1, in <module>
    from sklearn.linear_model import LogisticRegression
ModuleNotFoundError: No module named 'sklearn'"#;

    const PLAIN_ERROR: &str = "just some random stderr text without a Python exception";

    #[test]
    fn parse_returns_none_for_non_exception_text() {
        assert!(parse(PLAIN_ERROR).is_none());
    }

    #[test]
    fn parse_returns_none_for_empty_string() {
        assert!(parse("").is_none());
    }

    #[test]
    fn parse_module_not_found_code() {
        let tb = parse(MODULE_NOT_FOUND).unwrap();
        assert_eq!(tb.code, "E_RUNTIME_MODULE_NOT_FOUND");
    }

    #[test]
    fn parse_module_not_found_exception_type() {
        let tb = parse(MODULE_NOT_FOUND).unwrap();
        assert_eq!(tb.exception_type, "ModuleNotFoundError");
    }

    #[test]
    fn parse_module_not_found_message() {
        let tb = parse(MODULE_NOT_FOUND).unwrap();
        assert_eq!(tb.message, "No module named 'numpy'");
    }

    #[test]
    fn parse_module_not_found_location() {
        let tb = parse(MODULE_NOT_FOUND).unwrap();
        let loc = tb.location.unwrap();
        assert_eq!(loc.file, "app.py");
        assert_eq!(loc.line, 3);
        assert_eq!(loc.function, "<module>");
    }

    #[test]
    fn parse_module_not_found_next_action() {
        let tb = parse(MODULE_NOT_FOUND).unwrap();
        let action = tb.next_action.unwrap();
        assert_eq!(action.tool, "pybun_add");
        assert_eq!(action.args["package"], "numpy");
    }

    #[test]
    fn parse_subpackage_module_not_found_extracts_top_level() {
        let tb = parse(SUBPACKAGE_MODULE_NOT_FOUND).unwrap();
        let action = tb.next_action.unwrap();
        // Should suggest "sklearn" not "sklearn.linear_model"
        assert_eq!(action.args["package"], "sklearn");
    }

    #[test]
    fn parse_syntax_error_code() {
        let tb = parse(SYNTAX_ERROR).unwrap();
        assert_eq!(tb.code, "E_RUNTIME_SYNTAX_ERROR");
        assert_eq!(tb.exception_type, "SyntaxError");
    }

    #[test]
    fn parse_syntax_error_has_no_next_action() {
        let tb = parse(SYNTAX_ERROR).unwrap();
        assert!(tb.next_action.is_none());
    }

    #[test]
    fn parse_syntax_error_location() {
        let tb = parse(SYNTAX_ERROR).unwrap();
        let loc = tb.location.unwrap();
        assert_eq!(loc.file, "app.py");
        assert_eq!(loc.line, 5);
    }

    #[test]
    fn parse_type_error_code() {
        let tb = parse(TYPE_ERROR).unwrap();
        assert_eq!(tb.code, "E_RUNTIME_TYPE_ERROR");
        assert_eq!(tb.exception_type, "TypeError");
    }

    #[test]
    fn parse_type_error_location_innermost_frame() {
        let tb = parse(TYPE_ERROR).unwrap();
        let loc = tb.location.unwrap();
        assert_eq!(loc.file, "script.py");
        assert_eq!(loc.line, 10);
        assert_eq!(loc.function, "process");
    }

    #[test]
    fn parse_attribute_error_code() {
        let tb = parse(ATTRIBUTE_ERROR).unwrap();
        assert_eq!(tb.code, "E_RUNTIME_ATTRIBUTE_ERROR");
    }

    #[test]
    fn parse_name_error_code() {
        let tb = parse(NAME_ERROR).unwrap();
        assert_eq!(tb.code, "E_RUNTIME_NAME_ERROR");
    }

    #[test]
    fn parse_file_not_found_code() {
        let tb = parse(FILE_NOT_FOUND).unwrap();
        assert_eq!(tb.code, "E_RUNTIME_FILE_NOT_FOUND");
        assert_eq!(tb.exception_type, "FileNotFoundError");
    }

    #[test]
    fn parse_relative_path_strips_dot_slash() {
        let stderr = r#"Traceback (most recent call last):
  File "./src/main.py", line 1, in <module>
    pass
RuntimeError: boom"#;
        let tb = parse(stderr).unwrap();
        let loc = tb.location.unwrap();
        assert_eq!(loc.file, "src/main.py");
    }

    #[test]
    fn parse_absolute_path_under_current_dir_is_project_relative() {
        let absolute = std::env::current_dir().unwrap().join("src/main.py");
        let stderr = format!(
            r#"Traceback (most recent call last):
  File "{}", line 1, in <module>
    pass
RuntimeError: boom"#,
            absolute.display()
        );

        let tb = parse(&stderr).unwrap();
        let loc = tb.location.unwrap();
        assert_eq!(
            loc.file,
            std::path::Path::new("src/main.py").display().to_string()
        );
    }

    #[test]
    fn parse_bare_keyboard_interrupt_without_colon() {
        let stderr = r#"Traceback (most recent call last):
  File "main.py", line 1, in <module>
    raise KeyboardInterrupt
KeyboardInterrupt"#;

        let tb = parse(stderr).unwrap();
        assert_eq!(tb.code, "E_RUNTIME_INTERRUPTED");
        assert_eq!(tb.exception_type, "KeyboardInterrupt");
        assert_eq!(tb.message, "");
    }

    #[test]
    fn parse_unknown_exception_type() {
        let stderr = r#"Traceback (most recent call last):
  File "x.py", line 1, in <module>
    raise MyCustomError("oops")
MyCustomError: oops"#;
        let tb = parse(stderr).unwrap();
        assert_eq!(tb.code, "E_RUNTIME_UNKNOWN");
        assert_eq!(tb.exception_type, "MyCustomError");
    }

    #[test]
    fn parse_multiline_traceback_picks_innermost_frame() {
        let stderr = r#"Traceback (most recent call last):
  File "main.py", line 5, in main
    helper()
  File "utils.py", line 12, in helper
    inner()
  File "core.py", line 3, in inner
    raise ValueError("deep error")
ValueError: deep error"#;
        let tb = parse(stderr).unwrap();
        let loc = tb.location.unwrap();
        assert_eq!(loc.file, "core.py");
        assert_eq!(loc.line, 3);
        assert_eq!(loc.function, "inner");
    }

    #[test]
    fn extract_module_name_quoted() {
        assert_eq!(
            extract_module_name("No module named 'numpy'"),
            Some("numpy".to_string())
        );
    }

    #[test]
    fn extract_module_name_submodule_returns_top_level() {
        assert_eq!(
            extract_module_name("No module named 'sklearn.linear_model'"),
            Some("sklearn".to_string())
        );
    }

    #[test]
    fn map_import_error_with_no_module_message() {
        let code = map_exception_to_code("ImportError", "No module named 'requests'");
        assert_eq!(code, "E_RUNTIME_MODULE_NOT_FOUND");
    }

    #[test]
    fn map_import_error_without_no_module_message() {
        let code = map_exception_to_code("ImportError", "cannot import name 'foo' from 'bar'");
        assert_eq!(code, "E_RUNTIME_IMPORT_ERROR");
    }
}
