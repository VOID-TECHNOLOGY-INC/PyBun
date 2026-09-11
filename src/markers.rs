//! PEP 508 environment marker parsing and evaluation.

use crate::specifier::compare_versions;
use std::cmp::Ordering;
use std::sync::OnceLock;

/// A single token in a tokenized PEP 508 environment marker expression.
#[derive(Debug, Clone, PartialEq)]
enum MarkerToken {
    LParen,
    RParen,
    And,
    Or,
    Op(&'static str),
    Var(String),
    Str(String),
}

/// Tokenize a PEP 508 marker expression. Returns `None` if the input contains
/// syntax this tokenizer doesn't understand (unterminated strings, stray
/// operators, a bare `not` not followed by `in`, etc.) so the caller can fall
/// back to the inclusive default.
fn tokenize_marker(input: &str) -> Option<Vec<MarkerToken>> {
    let chars: Vec<char> = input.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }

        match c {
            '(' => {
                tokens.push(MarkerToken::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(MarkerToken::RParen);
                i += 1;
            }
            '\'' | '"' => {
                let quote = c;
                let start = i + 1;
                let mut j = start;
                while j < chars.len() && chars[j] != quote {
                    j += 1;
                }
                if j >= chars.len() {
                    return None; // unterminated string literal
                }
                tokens.push(MarkerToken::Str(chars[start..j].iter().collect()));
                i = j + 1;
            }
            '=' if chars.get(i + 1) == Some(&'=') => {
                tokens.push(MarkerToken::Op("=="));
                i += 2;
            }
            '!' if chars.get(i + 1) == Some(&'=') => {
                tokens.push(MarkerToken::Op("!="));
                i += 2;
            }
            '>' if chars.get(i + 1) == Some(&'=') => {
                tokens.push(MarkerToken::Op(">="));
                i += 2;
            }
            '<' if chars.get(i + 1) == Some(&'=') => {
                tokens.push(MarkerToken::Op("<="));
                i += 2;
            }
            '>' => {
                tokens.push(MarkerToken::Op(">"));
                i += 1;
            }
            '<' => {
                tokens.push(MarkerToken::Op("<"));
                i += 1;
            }
            c if c.is_alphanumeric() || c == '_' || c == '.' => {
                let start = i;
                while i < chars.len()
                    && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '.')
                {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                match word.as_str() {
                    "and" => tokens.push(MarkerToken::And),
                    "or" => tokens.push(MarkerToken::Or),
                    "in" => tokens.push(MarkerToken::Op("in")),
                    "not" => {
                        // PEP 508 only allows a bare `not` as part of `not in`.
                        let mut j = i;
                        while j < chars.len() && chars[j].is_whitespace() {
                            j += 1;
                        }
                        let word_start = j;
                        while j < chars.len() && (chars[j].is_alphanumeric() || chars[j] == '_') {
                            j += 1;
                        }
                        if chars[word_start..j].iter().collect::<String>() != "in" {
                            return None;
                        }
                        tokens.push(MarkerToken::Op("not in"));
                        i = j;
                    }
                    _ => tokens.push(MarkerToken::Var(word)),
                }
            }
            _ => return None, // unrecognized character
        }
    }

    Some(tokens)
}

/// One side of a marker comparison: either an environment variable
/// (e.g. `sys_platform`) or a quoted literal value (e.g. `"win32"`).
enum MarkerValue {
    Variable(String),
    Literal(String),
}

/// Recursive-descent parser over [`MarkerToken`]s implementing the PEP 508
/// `marker_or := marker_and ('or' marker_and)*` /
/// `marker_and := marker_expr ('and' marker_expr)*` grammar, with `and`
/// binding tighter than `or` and parentheses for grouping.
struct MarkerParser<'a> {
    tokens: &'a [MarkerToken],
    pos: usize,
}

impl MarkerParser<'_> {
    fn parse_or(&mut self) -> Option<bool> {
        let mut result = self.parse_and()?;
        while matches!(self.tokens.get(self.pos), Some(MarkerToken::Or)) {
            self.pos += 1;
            let rhs = self.parse_and()?;
            result = result || rhs;
        }
        Some(result)
    }

    fn parse_and(&mut self) -> Option<bool> {
        let mut result = self.parse_primary()?;
        while matches!(self.tokens.get(self.pos), Some(MarkerToken::And)) {
            self.pos += 1;
            let rhs = self.parse_primary()?;
            result = result && rhs;
        }
        Some(result)
    }

    fn parse_primary(&mut self) -> Option<bool> {
        if matches!(self.tokens.get(self.pos), Some(MarkerToken::LParen)) {
            self.pos += 1;
            let inner = self.parse_or()?;
            if !matches!(self.tokens.get(self.pos), Some(MarkerToken::RParen)) {
                return None;
            }
            self.pos += 1;
            return Some(inner);
        }
        self.parse_comparison()
    }

    fn parse_comparison(&mut self) -> Option<bool> {
        let left = self.parse_value()?;
        let op = match self.tokens.get(self.pos) {
            Some(MarkerToken::Op(op)) => *op,
            _ => return None,
        };
        self.pos += 1;
        let right = self.parse_value()?;
        Some(evaluate_comparison(&left, op, &right))
    }

    fn parse_value(&mut self) -> Option<MarkerValue> {
        match self.tokens.get(self.pos) {
            Some(MarkerToken::Var(name)) => {
                self.pos += 1;
                Some(MarkerValue::Variable(name.clone()))
            }
            Some(MarkerToken::Str(s)) => {
                self.pos += 1;
                Some(MarkerValue::Literal(s.clone()))
            }
            _ => None,
        }
    }
}

/// Look up the current environment's value for a PEP 508 marker variable.
/// Returns `None` for variables this evaluator doesn't know about (e.g. `extra`,
/// which is handled separately since the resolver doesn't track active extras).
fn lookup_marker_variable(name: &str) -> Option<String> {
    match name {
        "os_name" => Some(get_os_name().to_string()),
        "sys_platform" => Some(get_sys_platform().to_string()),
        "platform_machine" => Some(get_platform_machine().to_string()),
        "platform_system" => Some(get_platform_system().to_string()),
        "platform_release" => Some(get_platform_release()),
        "platform_version" => Some(get_platform_version()),
        "platform_python_implementation" => Some(get_python_implementation().to_string()),
        "implementation_name" => Some(get_python_implementation().to_lowercase()),
        "python_version" => Some(get_python_version().to_string()),
        "python_full_version" | "implementation_version" => {
            Some(get_python_full_version().to_string())
        }
        _ => None,
    }
}

/// Marker variables whose values are dotted version numbers and should be
/// compared numerically (via [`compare_versions`]) rather than lexically.
fn is_version_variable(value: &MarkerValue) -> bool {
    matches!(
        value,
        MarkerValue::Variable(name)
            if matches!(
                name.as_str(),
                "python_version" | "python_full_version" | "implementation_version"
            )
    )
}

fn is_extra_variable(value: &MarkerValue) -> bool {
    matches!(value, MarkerValue::Variable(name) if name == "extra")
}

fn resolve_marker_value(value: &MarkerValue) -> Option<String> {
    match value {
        MarkerValue::Literal(s) => Some(s.clone()),
        MarkerValue::Variable(name) => lookup_marker_variable(name),
    }
}

/// Evaluate a single `marker_var marker_op marker_var` comparison.
fn evaluate_comparison(left: &MarkerValue, op: &str, right: &MarkerValue) -> bool {
    // The resolver does not currently track which extras were requested, so
    // `extra == "..."` markers are treated as "extra not active" — consistent
    // with `marker_allows` in pypi.rs, which excludes all `extra ==` markers.
    if is_extra_variable(left) || is_extra_variable(right) {
        return match op {
            "==" | "in" => false,
            "!=" | "not in" => true,
            // Unsupported ordering operators on `extra` — be inclusive.
            _ => true,
        };
    }

    let (Some(lhs), Some(rhs)) = (resolve_marker_value(left), resolve_marker_value(right)) else {
        // Unknown variable → we don't know → be inclusive (don't silently drop packages).
        return true;
    };

    let version_aware = is_version_variable(left) || is_version_variable(right);

    match op {
        "==" => lhs == rhs,
        "!=" => lhs != rhs,
        // PEP 508 `in`/`not in`: true if the left value is a substring of the right value.
        "in" => rhs.contains(&lhs),
        "not in" => !rhs.contains(&lhs),
        ">=" | "<=" | ">" | "<" => {
            let ord = if version_aware {
                compare_versions(&lhs, &rhs)
            } else {
                lhs.cmp(&rhs)
            };
            match op {
                ">=" => ord != Ordering::Less,
                "<=" => ord != Ordering::Greater,
                ">" => ord == Ordering::Greater,
                "<" => ord == Ordering::Less,
                _ => unreachable!(),
            }
        }
        // Unsupported operator (e.g. `~=` in a marker) → be inclusive.
        _ => true,
    }
}

/// Evaluate a PEP 508 environment marker against the current platform.
///
/// Supports the full marker variable set (`os_name`, `sys_platform`,
/// `platform_machine`, `platform_system`, `platform_release`, `platform_version`,
/// `platform_python_implementation`, `implementation_name`, `python_version`,
/// `python_full_version`, `implementation_version`), all comparison operators
/// including `in`/`not in`, and quote-aware `and`/`or`/parentheses grouping.
///
/// If the marker can't be parsed, or contains a variable/operator this evaluator
/// doesn't understand, it returns `true` (inclusive) so packages are never
/// silently dropped due to an unrecognized marker.
pub(crate) fn evaluate_marker(marker: &str) -> bool {
    let marker = marker.trim();
    let Some(tokens) = tokenize_marker(marker) else {
        return true;
    };
    let mut parser = MarkerParser {
        tokens: &tokens,
        pos: 0,
    };
    match parser.parse_or() {
        Some(result) if parser.pos == tokens.len() => result,
        _ => true,
    }
}

/// Get the OS name in `os.name` form (`posix` or `nt`).
fn get_os_name() -> &'static str {
    #[cfg(windows)]
    return "nt";

    #[cfg(not(windows))]
    return "posix";
}

/// Detect the runtime Python version as a MAJOR.MINOR string (e.g. `"3.11"`).
///
/// Derived from [`get_python_full_version`], so no extra subprocess is spawned.
/// If Python cannot be detected, returns `"3.0"` as a conservative inclusive fallback.
pub(crate) fn get_python_version() -> &'static str {
    static PYTHON_VERSION: OnceLock<String> = OnceLock::new();
    PYTHON_VERSION.get_or_init(|| {
        let full = get_python_full_version();
        let parts: Vec<&str> = full.split('.').collect();
        if parts.len() >= 2 {
            format!("{}.{}", parts[0], parts[1])
        } else {
            "3.0".to_string()
        }
    })
}

/// Detect the full runtime Python version as `MAJOR.MINOR.PATCH` (e.g. `"3.11.4"`).
///
/// The result is cached in a `OnceLock` so the subprocess is only spawned once per process.
/// If Python cannot be detected, returns `"3.0.0"` as a conservative inclusive fallback.
fn get_python_full_version() -> &'static str {
    static FULL_VERSION: OnceLock<String> = OnceLock::new();
    FULL_VERSION.get_or_init(|| {
        for cmd in &["python3", "python"] {
            let Ok(output) = std::process::Command::new(cmd).arg("--version").output() else {
                continue;
            };
            if !output.status.success() {
                continue;
            }
            // Python 2 prints to stderr; Python 3 prints to stdout.
            let raw = if output.stdout.is_empty() {
                output.stderr
            } else {
                output.stdout
            };
            let text = String::from_utf8_lossy(&raw);
            if let Some(ver) = text.trim().strip_prefix("Python ")
                && !ver.is_empty()
            {
                return ver.to_string();
            }
        }
        // Fallback: inclusive — do not silently drop packages.
        "3.0.0".to_string()
    })
}

/// Detect the running Python implementation (e.g. `"CPython"`, `"PyPy"`).
///
/// The result is cached in a `OnceLock` so the subprocess is only spawned once per process.
/// If Python cannot be detected, returns `"CPython"` — the overwhelmingly common case,
/// which keeps CPython-targeted markers inclusive while still letting
/// implementation-specific markers (e.g. PyPy-only deps) evaluate correctly when detection
/// succeeds.
fn get_python_implementation() -> &'static str {
    static IMPLEMENTATION: OnceLock<String> = OnceLock::new();
    IMPLEMENTATION.get_or_init(|| {
        for cmd in &["python3", "python"] {
            let Ok(output) = std::process::Command::new(cmd)
                .args([
                    "-c",
                    "import platform; print(platform.python_implementation())",
                ])
                .output()
            else {
                continue;
            };
            if !output.status.success() {
                continue;
            }
            let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !text.is_empty() {
                return text;
            }
        }
        "CPython".to_string()
    })
}

/// Get the OS release version via `uname -r` (e.g. `"23.1.0"`).
///
/// Returns an empty string on platforms where this can't be determined, which compares
/// as "less than" any non-empty release string in ordering comparisons.
fn get_platform_release() -> String {
    static RELEASE: OnceLock<String> = OnceLock::new();
    RELEASE
        .get_or_init(|| {
            #[cfg(unix)]
            {
                if let Ok(output) = std::process::Command::new("uname").arg("-r").output()
                    && output.status.success()
                {
                    return String::from_utf8_lossy(&output.stdout).trim().to_string();
                }
            }
            String::new()
        })
        .clone()
}

/// Get the detailed OS version string via `uname -v`.
///
/// Returns an empty string on platforms where this can't be determined.
fn get_platform_version() -> String {
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION
        .get_or_init(|| {
            #[cfg(unix)]
            {
                if let Ok(output) = std::process::Command::new("uname").arg("-v").output()
                    && output.status.success()
                {
                    return String::from_utf8_lossy(&output.stdout).trim().to_string();
                }
            }
            String::new()
        })
        .clone()
}

/// Get the platform machine architecture (e.g., 'x86_64', 'arm64', 'i386').
fn get_platform_machine() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    return "x86_64";

    #[cfg(target_arch = "aarch64")]
    {
        // Python on macOS reports aarch64 as 'arm64'
        #[cfg(target_os = "macos")]
        return "arm64";

        #[cfg(not(target_os = "macos"))]
        return "aarch64";
    }

    #[cfg(target_arch = "x86")]
    return "i386";

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "x86")))]
    return "unknown";
}

/// Get the system platform (e.g., 'darwin', 'linux', 'win32').
fn get_sys_platform() -> &'static str {
    #[cfg(target_os = "macos")]
    return "darwin";

    #[cfg(target_os = "linux")]
    return "linux";

    #[cfg(target_os = "windows")]
    return "win32";

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    return "unknown";
}

/// Get the platform system (e.g., 'Darwin', 'Linux', 'Windows').
fn get_platform_system() -> &'static str {
    #[cfg(target_os = "macos")]
    return "Darwin";

    #[cfg(target_os = "linux")]
    return "Linux";

    #[cfg(target_os = "windows")]
    return "Windows";

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    return "Unknown";
}
