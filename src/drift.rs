//! Dependency drift detection via static import analysis.
//!
//! Phase 1: regex/token-based import scanning.
//! Cross-references Python `import` statements with `pyproject.toml` declarations.

use crate::project::Project;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// A single location where an import appears.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportLocation {
    pub file: String,
    pub line: usize,
    pub statement: String,
}

/// A package that is imported but not declared in pyproject.toml.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndeclaredImport {
    pub package: String,
    pub imported_in: Vec<ImportLocation>,
    pub next_action: NextAction,
}

/// A package that is declared in pyproject.toml but never imported.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnusedDeclaration {
    pub package: String,
    /// Every declaration scope the package appears in (Issue #409), e.g.
    /// `["project.dependencies"]`, `["project.optional-dependencies.ml"]`, or
    /// `["dependency-groups.dev", "dependency-groups.test"]` when declared
    /// (or reachable via `include-group`) in more than one place.
    pub declared_in: Vec<String>,
    pub next_action: NextAction,
}

/// A structured agent-callable action to remediate drift.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextAction {
    pub tool: String,
    pub args: HashMap<String, String>,
}

/// Result of a drift analysis run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftResult {
    pub undeclared_imports: Vec<UndeclaredImport>,
    pub unused_declarations: Vec<UnusedDeclaration>,
    pub analysis_notes: Vec<String>,
    pub files_scanned: usize,
}

/// Perform drift analysis in the given directory.
pub fn analyze(root: &Path) -> DriftResult {
    let pyproject_path = root.join("pyproject.toml");

    // Collect all .py files recursively
    let py_files = collect_py_files(root);
    let files_scanned = py_files.len();

    // Scan all imports
    let mut import_map: HashMap<String, Vec<ImportLocation>> = HashMap::new();
    for py_file in &py_files {
        let file_label = py_file
            .strip_prefix(root)
            .unwrap_or(py_file)
            .to_string_lossy()
            .to_string();
        if let Ok(content) = std::fs::read_to_string(py_file) {
            for (line_no, line) in logical_import_lines(&content) {
                let line = line.trim();
                let pkgs = parse_import_packages(line);
                if !pkgs.is_empty() {
                    let loc = ImportLocation {
                        file: file_label.clone(),
                        line: line_no,
                        statement: line.to_string(),
                    };
                    for pkg in pkgs {
                        import_map.entry(pkg).or_default().push(loc.clone());
                    }
                }
            }
        }
    }

    // Resolve import names to PyPI package names
    let aliases = import_aliases();
    let resolved: HashMap<String, (String, Vec<ImportLocation>)> = import_map
        .into_iter()
        .map(|(import_name, locs)| {
            let pypi_name = aliases
                .get(import_name.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| import_name.clone());
            (import_name, (pypi_name, locs))
        })
        .collect();

    // Build the set of PyPI names that are actually imported (non-stdlib only)
    let stdlib = stdlib_modules();
    let mut imported_pypi: HashMap<String, Vec<ImportLocation>> = HashMap::new();
    for (import_name, (pypi_name, locs)) in &resolved {
        if !stdlib.contains(import_name.as_str()) {
            let entry = imported_pypi
                .entry(normalize_package_name(pypi_name))
                .or_default();
            entry.extend(locs.iter().cloned());
        }
    }

    // Load declared dependencies from pyproject.toml (best-effort), reusing
    // Project's existing dependency model (Issue #409) instead of a narrower
    // duplicate parser that only understood `[project.dependencies]`. This
    // also picks up `[project.optional-dependencies]` and PEP 735
    // `[dependency-groups]` (with `include-group` expansion already handled
    // by `Project::dependency_groups()`), so packages declared in those
    // scopes are no longer falsely reported as globally undeclared.
    let declared_entries: Vec<(String, String)> = if pyproject_path.exists() {
        match Project::load(&pyproject_path) {
            Ok(project) => {
                let mut entries: Vec<(String, String)> = project
                    .dependencies()
                    .into_iter()
                    .map(|dep| (dep, "project.dependencies".to_string()))
                    .collect();
                for (group, deps) in project.optional_dependencies() {
                    let scope = format!("project.optional-dependencies.{group}");
                    entries.extend(deps.into_iter().map(|dep| (dep, scope.clone())));
                }
                for (group, deps) in project.dependency_groups() {
                    let scope = format!("dependency-groups.{group}");
                    entries.extend(deps.into_iter().map(|dep| (dep, scope.clone())));
                }
                entries
            }
            Err(_) => Vec::new(),
        }
    } else {
        Vec::new()
    };

    // Group declared entries by normalized package name: a package declared
    // in more than one scope (e.g. both `dependency-groups.dev` and
    // `dependency-groups.test` via `include-group`) is declared once, with
    // every contributing scope recorded for JSON output.
    struct DeclaredPackage {
        display_name: String,
        scopes: Vec<String>,
    }
    let mut declared_by_package: HashMap<String, DeclaredPackage> = HashMap::new();
    for (spec, scope) in &declared_entries {
        let display_name = extract_package_name_from_dep(spec);
        let normalized = normalize_package_name(&display_name);
        let entry = declared_by_package
            .entry(normalized)
            .or_insert_with(|| DeclaredPackage {
                display_name: display_name.clone(),
                scopes: Vec::new(),
            });
        if !entry.scopes.contains(scope) {
            entry.scopes.push(scope.clone());
        }
    }

    // A package declared in *any* recognized scope counts as declared for
    // repository-wide undeclared-import detection (Phase 1 of #409 — scope
    // mismatches, e.g. runtime code importing a dev-only dependency, are not
    // yet distinguished from a globally valid declaration).
    let declared_normalized: HashSet<String> = declared_by_package.keys().cloned().collect();

    // Find undeclared imports
    let mut undeclared_imports: Vec<UndeclaredImport> = imported_pypi
        .into_iter()
        .filter(|(pypi_name, _)| !declared_normalized.contains(pypi_name.as_str()))
        .map(|(pypi_name, locs)| {
            let mut args = HashMap::new();
            args.insert("package".to_string(), pypi_name.clone());
            UndeclaredImport {
                package: pypi_name,
                imported_in: locs,
                next_action: NextAction {
                    tool: "pybun_add".to_string(),
                    args,
                },
            }
        })
        .collect();
    undeclared_imports.sort_by(|a, b| a.package.cmp(&b.package));

    // Find unused declarations
    let import_aliases_rev = import_aliases_reverse(&aliases);
    let mut unused_declarations: Vec<UnusedDeclaration> = declared_by_package
        .into_iter()
        .filter(|(name, _)| {
            // Check if this pypi name (or any of its import aliases) appears in imports
            let alt_import = import_aliases_rev.get(name.as_str());
            let is_used = resolved
                .values()
                .any(|(pypi, _)| &normalize_package_name(pypi) == name)
                || alt_import.is_some_and(|aliases| {
                    aliases.iter().any(|alias| resolved.contains_key(*alias))
                });
            !is_used
        })
        .map(|(_, declared)| {
            let mut args = HashMap::new();
            args.insert("package".to_string(), declared.display_name.clone());
            UnusedDeclaration {
                package: declared.display_name,
                declared_in: declared.scopes,
                next_action: NextAction {
                    tool: "pybun_remove".to_string(),
                    args,
                },
            }
        })
        .collect();
    unused_declarations.sort_by(|a, b| a.package.cmp(&b.package));

    let mut analysis_notes = vec![
        "dynamic imports (importlib.import_module) not detected".to_string(),
        "TYPE_CHECKING blocks not excluded from analysis".to_string(),
    ];
    if files_scanned == 0 {
        analysis_notes.push("no Python files found in directory".to_string());
    }

    DriftResult {
        undeclared_imports,
        unused_declarations,
        analysis_notes,
        files_scanned,
    }
}

/// Collect all .py files recursively, skipping hidden dirs and common noise dirs.
fn collect_py_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    // Track canonical (symlink-resolved) directory paths we've already
    // descended into, so a symlink cycle (e.g. `a/loop -> a`) can't send the
    // traversal into unbounded recursion / a stack overflow.
    let mut visited_dirs: HashSet<PathBuf> = HashSet::new();
    if let Ok(canonical_root) = std::fs::canonicalize(root) {
        visited_dirs.insert(canonical_root);
    }
    collect_py_files_inner(root, &mut files, &mut visited_dirs);
    files
}

fn collect_py_files_inner(dir: &Path, out: &mut Vec<PathBuf>, visited_dirs: &mut HashSet<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Skip hidden dirs and common noise dirs
        if name_str.starts_with('.') {
            continue;
        }
        if matches!(
            name_str.as_ref(),
            "__pycache__"
                | ".venv"
                | "venv"
                | "env"
                | "node_modules"
                | "dist"
                | "build"
                | "site-packages"
                | ".pybun"
        ) {
            continue;
        }

        if path.is_dir() {
            // Resolve symlinks before recursing: if we've already visited
            // this canonical directory (directly or via a different
            // symlinked path), skip it rather than recursing again.
            match std::fs::canonicalize(&path) {
                Ok(canonical) => {
                    if !visited_dirs.insert(canonical) {
                        continue;
                    }
                }
                Err(_) => continue,
            }
            collect_py_files_inner(&path, out, visited_dirs);
        } else if path.extension().is_some_and(|e| e == "py") {
            out.push(path);
        }
    }
}

/// Preprocess Python source into logical `(line_no, text)` pairs suitable
/// for `parse_import_packages`.
///
/// Two transformations are applied that plain `content.lines()` iteration
/// gets wrong:
/// - Lines inside a triple-quoted string (`"""..."""` or `'''...'''`) are
///   dropped entirely, so prose inside a docstring that happens to read like
///   an import statement (e.g. a usage example) is never mistaken for real
///   code.
/// - A physical line ending in a bare `\` is joined with the next physical
///   line, so a backslash-continued `import a, \` statement is parsed as
///   one logical statement instead of losing the continuation packages (and
///   emitting a spurious `\` "package" from the dangling backslash).
///
/// `line_no` is the 1-based line number of the *first* physical line of each
/// logical line, matching the numbering used for reporting.
fn logical_import_lines(content: &str) -> Vec<(usize, String)> {
    const TRIPLE_QUOTES: [&str; 2] = ["\"\"\"", "'''"];

    let mut out = Vec::new();
    let mut in_triple: Option<&'static str> = None;
    let mut pending: Option<(usize, String)> = None;

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;

        if let Some(delim) = in_triple {
            if raw_line.matches(delim).count() % 2 == 1 {
                in_triple = None;
            }
            continue;
        }

        // Does this line open a triple-quoted string that doesn't also
        // close again on the same line? If so, everything from here until
        // the matching close is string content, not code.
        //
        // KNOWN LIMITATION: this count-based heuristic does not distinguish
        // triple-quote delimiters from `"""` / `'''` sequences that appear
        // inside regular string literals. A full fix requires Python
        // tokenization.
        let mut scan_line = raw_line;
        for delim in TRIPLE_QUOTES {
            if raw_line.matches(delim).count() % 2 == 1 {
                in_triple = Some(delim);
                scan_line = "";
                break;
            }
        }

        let trimmed_end = scan_line.trim_end();
        // A `#` comment that ends with `\` does NOT continue in Python.
        let continues = !scan_line.trim_start().starts_with('#') && trimmed_end.ends_with('\\');
        let content_part = if continues {
            &trimmed_end[..trimmed_end.len() - 1]
        } else {
            scan_line
        };

        pending = Some(match pending.take() {
            Some((first_line, mut acc)) => {
                acc.push(' ');
                acc.push_str(content_part.trim());
                (first_line, acc)
            }
            None => (line_no, content_part.to_string()),
        });

        if !continues {
            out.push(pending.take().expect("just set above"));
        }
    }

    if let Some(p) = pending {
        out.push(p);
    }

    out
}

/// Parse a single Python source line and extract top-level package names.
/// Returns an empty vec for non-import lines, comments, relative imports, and __future__.
/// Handles `import a, b, c` by returning all packages.
pub fn parse_import_packages(line: &str) -> Vec<String> {
    let line = line.trim();

    if line.starts_with('#') || line.is_empty() {
        return vec![];
    }

    // `from X import Y` — skip relative and __future__
    if let Some(rest) = line.strip_prefix("from ") {
        let module = match rest.split_whitespace().next() {
            Some(m) => m,
            None => return vec![],
        };
        if module.starts_with('.') || module == "__future__" {
            return vec![];
        }
        let top_level = match module.split('.').next() {
            Some(t) => t,
            None => return vec![],
        };
        return vec![top_level.to_string()];
    }

    // `import a, b.c, d as e` — collect all top-level packages
    if let Some(rest) = line.strip_prefix("import ") {
        return rest
            .split(',')
            .filter_map(|segment| {
                // strip trailing `as alias`
                let module = segment.split_whitespace().next()?;
                module.split('.').next().map(|s| s.to_string())
            })
            .collect();
    }

    vec![]
}

/// Compatibility shim — returns the first package from `parse_import_packages`.
#[cfg(test)]
pub fn parse_import_line(line: &str) -> Option<String> {
    parse_import_packages(line).into_iter().next()
}

/// Normalize a package name for comparison (lowercase, hyphens→underscores).
fn normalize_package_name(name: &str) -> String {
    name.to_lowercase().replace('-', "_")
}

/// Extract bare package name from a PEP 508 dependency specifier.
fn extract_package_name_from_dep(dep: &str) -> String {
    // PEP 508 delimiters: extras (`[`), a version specifier operator
    // (`==`, `!=`, `<=`, `>=`, `<`, `>`, `~=`, `===`), an environment
    // marker (`;`), a direct URL reference (`@`), or whitespace.
    dep.split(['>', '<', '=', '!', '~', '@', '[', ';', ' ', '\t'])
        .next()
        .unwrap_or(dep)
        .trim()
        .to_string()
}

/// Mapping from Python import name → PyPI package name for known aliases.
pub fn import_aliases() -> HashMap<&'static str, &'static str> {
    let mut m = HashMap::new();
    // Common aliases where import name differs from PyPI name
    m.insert("PIL", "Pillow");
    m.insert("cv2", "opencv-python");
    m.insert("sklearn", "scikit-learn");
    m.insert("skimage", "scikit-image");
    m.insert("bs4", "beautifulsoup4");
    m.insert("yaml", "PyYAML");
    m.insert("dotenv", "python-dotenv");
    m.insert("dateutil", "python-dateutil");
    m.insert("google", "google-cloud-core");
    m.insert("Crypto", "pycryptodome");
    m.insert("jwt", "PyJWT");
    m.insert("MySQLdb", "mysqlclient");
    m.insert("psycopg2", "psycopg2-binary");
    m.insert("attr", "attrs");
    m.insert("wx", "wxPython");
    m.insert("gi", "PyGObject");
    m.insert("usb", "pyusb");
    m.insert("serial", "pyserial");
    m.insert("magic", "python-magic");
    m
}

/// Reverse mapping: PyPI name → list of possible import names.
///
/// Takes the already-built `import_aliases()` map rather than building its
/// own copy, since it's derived data from the same table (avoids rebuilding
/// the alias `HashMap` twice per `analyze()` call).
fn import_aliases_reverse(
    aliases: &HashMap<&'static str, &'static str>,
) -> HashMap<&'static str, Vec<&'static str>> {
    let mut m: HashMap<&'static str, Vec<&'static str>> = HashMap::new();
    for (import_name, pypi_name) in aliases {
        m.entry(*pypi_name).or_default().push(*import_name);
    }
    m
}

/// Set of Python standard library module names to exclude from drift analysis.
pub fn stdlib_modules() -> HashSet<&'static str> {
    // Python 3.9+ stdlib (comprehensive list)
    [
        "__future__",
        "_thread",
        "abc",
        "aifc",
        "argparse",
        "array",
        "ast",
        "asynchat",
        "asyncio",
        "asyncore",
        "atexit",
        "audioop",
        "base64",
        "bdb",
        "binascii",
        "binhex",
        "bisect",
        "builtins",
        "bz2",
        "calendar",
        "cgi",
        "cgitb",
        "chunk",
        "cmath",
        "cmd",
        "code",
        "codecs",
        "codeop",
        "colorsys",
        "compileall",
        "concurrent",
        "configparser",
        "contextlib",
        "contextvars",
        "copy",
        "copyreg",
        "cProfile",
        "csv",
        "ctypes",
        "curses",
        "dataclasses",
        "datetime",
        "dbm",
        "decimal",
        "difflib",
        "dis",
        "distutils",
        "doctest",
        "email",
        "encodings",
        "enum",
        "errno",
        "faulthandler",
        "fcntl",
        "filecmp",
        "fileinput",
        "fnmatch",
        "fractions",
        "ftplib",
        "functools",
        "gc",
        "getopt",
        "getpass",
        "gettext",
        "glob",
        "grp",
        "gzip",
        "hashlib",
        "heapq",
        "hmac",
        "html",
        "http",
        "idlelib",
        "imaplib",
        "imghdr",
        "importlib",
        "inspect",
        "io",
        "ipaddress",
        "itertools",
        "json",
        "keyword",
        "lib2to3",
        "linecache",
        "locale",
        "logging",
        "lzma",
        "mailbox",
        "mailcap",
        "marshal",
        "math",
        "mimetypes",
        "mmap",
        "modulefinder",
        "multiprocessing",
        "netrc",
        "nis",
        "nntplib",
        "numbers",
        "operator",
        "optparse",
        "os",
        "ossaudiodev",
        "pathlib",
        "pdb",
        "pickle",
        "pickletools",
        "pipes",
        "pkgutil",
        "platform",
        "plistlib",
        "poplib",
        "posix",
        "posixpath",
        "pprint",
        "profile",
        "pstats",
        "pty",
        "pwd",
        "py_compile",
        "pyclbr",
        "pydoc",
        "queue",
        "quopri",
        "random",
        "re",
        "readline",
        "reprlib",
        "resource",
        "rlcompleter",
        "runpy",
        "sched",
        "secrets",
        "select",
        "selectors",
        "shelve",
        "shlex",
        "shutil",
        "signal",
        "site",
        "smtpd",
        "smtplib",
        "sndhdr",
        "socket",
        "socketserver",
        "spwd",
        "sqlite3",
        "sre_compile",
        "sre_constants",
        "sre_parse",
        "ssl",
        "stat",
        "statistics",
        "string",
        "stringprep",
        "struct",
        "subprocess",
        "sunau",
        "symtable",
        "sys",
        "sysconfig",
        "syslog",
        "tabnanny",
        "tarfile",
        "telnetlib",
        "tempfile",
        "termios",
        "test",
        "textwrap",
        "threading",
        "time",
        "timeit",
        "tkinter",
        "token",
        "tokenize",
        "tomllib",
        "trace",
        "traceback",
        "tracemalloc",
        "tty",
        "turtle",
        "turtledemo",
        "types",
        "typing",
        "unicodedata",
        "unittest",
        "urllib",
        "uu",
        "uuid",
        "venv",
        "warnings",
        "wave",
        "weakref",
        "webbrowser",
        "winreg",
        "winsound",
        "wsgiref",
        "xdrlib",
        "xml",
        "xmlrpc",
        "zipapp",
        "zipfile",
        "zipimport",
        "zlib",
        "zoneinfo",
        // Common first-party / test modules that aren't on PyPI
        "conftest",
        "setup",
        "manage",
        "__init__",
        "__main__",
    ]
    .into_iter()
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_import_line_simple_import() {
        assert_eq!(
            parse_import_line("import pandas"),
            Some("pandas".to_string())
        );
    }

    #[test]
    fn parse_import_line_from_import() {
        assert_eq!(
            parse_import_line("from requests import get"),
            Some("requests".to_string())
        );
    }

    #[test]
    fn parse_import_line_from_submodule() {
        assert_eq!(
            parse_import_line("from requests.auth import HTTPBasicAuth"),
            Some("requests".to_string())
        );
    }

    #[test]
    fn parse_import_line_import_as() {
        assert_eq!(
            parse_import_line("import numpy as np"),
            Some("numpy".to_string())
        );
    }

    #[test]
    fn parse_import_packages_multi_import() {
        let pkgs = parse_import_packages("import os, sys, json");
        assert_eq!(pkgs, vec!["os", "sys", "json"]);
    }

    #[test]
    fn parse_import_packages_multi_import_with_alias() {
        let pkgs = parse_import_packages("import numpy as np, pandas as pd");
        assert_eq!(pkgs, vec!["numpy", "pandas"]);
    }

    #[test]
    fn parse_import_packages_single_import() {
        let pkgs = parse_import_packages("import requests");
        assert_eq!(pkgs, vec!["requests"]);
    }

    #[test]
    fn parse_import_line_relative_import_skipped() {
        assert_eq!(parse_import_line("from . import util"), None);
        assert_eq!(parse_import_line("from ..models import User"), None);
    }

    #[test]
    fn parse_import_line_future_skipped() {
        assert_eq!(
            parse_import_line("from __future__ import annotations"),
            None
        );
    }

    #[test]
    fn parse_import_line_comment_skipped() {
        assert_eq!(parse_import_line("# import requests"), None);
    }

    #[test]
    fn parse_import_line_non_import_skipped() {
        assert_eq!(parse_import_line("x = 1"), None);
        assert_eq!(parse_import_line(""), None);
    }

    #[test]
    fn stdlib_modules_contains_common_stdlib() {
        let stdlib = stdlib_modules();
        assert!(stdlib.contains("os"));
        assert!(stdlib.contains("sys"));
        assert!(stdlib.contains("json"));
        assert!(stdlib.contains("re"));
        assert!(stdlib.contains("math"));
        assert!(stdlib.contains("pathlib"));
    }

    #[test]
    fn stdlib_modules_excludes_third_party() {
        let stdlib = stdlib_modules();
        assert!(!stdlib.contains("requests"));
        assert!(!stdlib.contains("numpy"));
        assert!(!stdlib.contains("pandas"));
    }

    #[test]
    fn import_aliases_pil_maps_to_pillow() {
        let aliases = import_aliases();
        assert_eq!(aliases.get("PIL"), Some(&"Pillow"));
    }

    #[test]
    fn import_aliases_cv2_maps_to_opencv() {
        let aliases = import_aliases();
        assert_eq!(aliases.get("cv2"), Some(&"opencv-python"));
    }

    #[test]
    fn normalize_package_name_lowercases_and_replaces_hyphens() {
        assert_eq!(normalize_package_name("PyYAML"), "pyyaml");
        assert_eq!(normalize_package_name("scikit-learn"), "scikit_learn");
        assert_eq!(normalize_package_name("opencv-python"), "opencv_python");
    }

    #[test]
    fn extract_package_name_strips_version_specifier() {
        assert_eq!(extract_package_name_from_dep("requests>=2.28"), "requests");
        assert_eq!(extract_package_name_from_dep("numpy==1.24.0"), "numpy");
        assert_eq!(extract_package_name_from_dep("flask[async]"), "flask");
        assert_eq!(extract_package_name_from_dep("pandas"), "pandas");
    }

    #[test]
    fn analyze_detects_undeclared() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname=\"t\"\nversion=\"0.1\"\ndependencies=[\"requests\"]\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("main.py"),
            "import pandas\nimport requests\n",
        )
        .unwrap();
        let result = analyze(dir.path());
        let pkgs: Vec<&str> = result
            .undeclared_imports
            .iter()
            .map(|u| u.package.as_str())
            .collect();
        assert!(pkgs.contains(&"pandas"));
        assert!(!pkgs.contains(&"requests"));
    }

    #[test]
    fn analyze_detects_unused() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname=\"t\"\nversion=\"0.1\"\ndependencies=[\"requests\",\"numpy\"]\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("main.py"), "import requests\n").unwrap();
        let result = analyze(dir.path());
        let pkgs: Vec<&str> = result
            .unused_declarations
            .iter()
            .map(|u| u.package.as_str())
            .collect();
        assert!(pkgs.contains(&"numpy"));
        assert!(!pkgs.contains(&"requests"));
    }

    #[test]
    fn analyze_clean_project_is_empty() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname=\"t\"\nversion=\"0.1\"\ndependencies=[\"requests\"]\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("main.py"), "import requests\n").unwrap();
        let result = analyze(dir.path());
        assert!(result.undeclared_imports.is_empty());
        assert!(result.unused_declarations.is_empty());
    }

    #[test]
    fn analyze_excludes_stdlib() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname=\"t\"\nversion=\"0.1\"\ndependencies=[]\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("main.py"), "import os\nimport sys\n").unwrap();
        let result = analyze(dir.path());
        assert!(
            result.undeclared_imports.is_empty(),
            "stdlib must not appear in undeclared"
        );
    }

    #[test]
    fn analyze_pil_resolves_to_pillow() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname=\"t\"\nversion=\"0.1\"\ndependencies=[\"Pillow\"]\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("main.py"), "from PIL import Image\n").unwrap();
        let result = analyze(dir.path());
        assert!(
            result.undeclared_imports.is_empty(),
            "PIL should resolve to Pillow"
        );
        // Pillow should not be in unused either
        assert!(result.unused_declarations.is_empty());
    }

    #[test]
    fn analyze_next_action_for_undeclared_is_pybun_add() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname=\"t\"\nversion=\"0.1\"\ndependencies=[]\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("main.py"), "import pandas\n").unwrap();
        let result = analyze(dir.path());
        let entry = result.undeclared_imports.first().unwrap();
        assert_eq!(entry.next_action.tool, "pybun_add");
        assert_eq!(entry.next_action.args.get("package").unwrap(), "pandas");
    }

    #[test]
    fn analyze_next_action_for_unused_is_pybun_remove() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname=\"t\"\nversion=\"0.1\"\ndependencies=[\"numpy\"]\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("main.py"), "# empty\n").unwrap();
        let result = analyze(dir.path());
        let entry = result.unused_declarations.first().unwrap();
        assert_eq!(entry.next_action.tool, "pybun_remove");
        assert_eq!(entry.next_action.args.get("package").unwrap(), "numpy");
    }

    #[test]
    fn collect_py_files_finds_files_in_subdirs() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("main.py"), "").unwrap();
        std::fs::write(dir.path().join("src/util.py"), "").unwrap();
        let files = collect_py_files(dir.path());
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn collect_py_files_skips_pycache() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("__pycache__")).unwrap();
        std::fs::write(dir.path().join("main.py"), "").unwrap();
        std::fs::write(dir.path().join("__pycache__/main.cpython-311.pyc"), "").unwrap();
        let files = collect_py_files(dir.path());
        // .pyc files won't be picked up (.py extension only), but __pycache__ is also skipped
        assert_eq!(files.len(), 1);
    }

    #[test]
    #[cfg(unix)]
    fn collect_py_files_handles_symlink_cycle() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("a")).unwrap();
        std::fs::write(dir.path().join("a/mod.py"), "").unwrap();
        // `a/loop` symlinks back to the root, forming a cycle. Traversal
        // must detect and skip the repeat instead of recursing forever.
        std::os::unix::fs::symlink(dir.path(), dir.path().join("a/loop")).unwrap();

        let files = collect_py_files(dir.path());
        assert_eq!(files.len(), 1, "should find exactly the one real .py file");
    }

    #[test]
    fn extract_package_name_strips_tilde_and_at_specifiers() {
        assert_eq!(extract_package_name_from_dep("requests~=2.28"), "requests");
        assert_eq!(
            extract_package_name_from_dep("requests @ https://example.com/requests.whl"),
            "requests"
        );
    }

    #[test]
    fn import_aliases_never_self_map() {
        for (import_name, pypi_name) in import_aliases() {
            assert_ne!(
                import_name, pypi_name,
                "alias entry for {import_name} maps to itself, defeating its purpose"
            );
        }
    }

    #[test]
    fn logical_import_lines_joins_backslash_continuation() {
        let content = "import numpy, \\\n    pandas\n";
        let lines = logical_import_lines(content);
        assert_eq!(lines.len(), 1);
        let pkgs = parse_import_packages(lines[0].1.trim());
        assert_eq!(pkgs, vec!["numpy", "pandas"]);
    }

    #[test]
    fn logical_import_lines_does_not_continue_past_comment_backslash() {
        let content = "# see usage: \\\nimport pandas\n";
        let lines = logical_import_lines(content);
        let all_pkgs: Vec<String> = lines
            .iter()
            .flat_map(|(_, line)| parse_import_packages(line.trim()))
            .collect();
        assert_eq!(all_pkgs, vec!["pandas"]);
    }

    #[test]
    fn logical_import_lines_skips_triple_quoted_string_content() {
        let content = "def foo():\n    \"\"\"\n    import pandas\n    \"\"\"\n    import sys\n";
        let lines = logical_import_lines(content);
        let all_pkgs: Vec<String> = lines
            .iter()
            .flat_map(|(_, line)| parse_import_packages(line.trim()))
            .collect();
        assert_eq!(all_pkgs, vec!["sys"]);
    }

    #[test]
    fn analyze_ignores_imports_inside_docstrings() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname=\"t\"\nversion=\"0.1\"\ndependencies=[\"requests\"]\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("main.py"),
            "def foo():\n    \"\"\"\n    Example:\n        import pandas\n    \"\"\"\n    pass\n\nimport requests\n",
        )
        .unwrap();
        let result = analyze(dir.path());
        let pkgs: Vec<&str> = result
            .undeclared_imports
            .iter()
            .map(|u| u.package.as_str())
            .collect();
        assert!(
            !pkgs.contains(&"pandas"),
            "docstring example import must not be detected: {pkgs:?}"
        );
    }

    #[test]
    fn analyze_detects_backslash_continued_import() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname=\"t\"\nversion=\"0.1\"\ndependencies=[]\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("main.py"), "import numpy, \\\n    pandas\n").unwrap();
        let result = analyze(dir.path());
        let pkgs: Vec<&str> = result
            .undeclared_imports
            .iter()
            .map(|u| u.package.as_str())
            .collect();
        assert!(pkgs.contains(&"numpy"));
        assert!(pkgs.contains(&"pandas"));
        assert!(
            !pkgs.iter().any(|p| p.contains('\\')),
            "must not register a spurious backslash package: {pkgs:?}"
        );
    }

    // =========================================================================
    // Issue #409: declared-dependency parsing must reuse Project's dependency
    // model (main deps, optional-dependencies, dependency-groups + PEP 735
    // include-group expansion), not a narrower duplicate parser.
    // =========================================================================

    #[test]
    fn analyze_optional_dependency_is_not_falsely_undeclared() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname=\"t\"\nversion=\"0.1\"\ndependencies=[\"requests\"]\n\n\
             [project.optional-dependencies]\nml = [\"numpy\", \"pandas\"]\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("ml.py"), "import numpy\nimport pandas\n").unwrap();

        let result = analyze(dir.path());
        let undeclared: Vec<&str> = result
            .undeclared_imports
            .iter()
            .map(|u| u.package.as_str())
            .collect();
        assert!(
            !undeclared.contains(&"numpy") && !undeclared.contains(&"pandas"),
            "packages declared in [project.optional-dependencies] must not be \
             reported as undeclared: {undeclared:?}"
        );
    }

    #[test]
    fn analyze_dependency_group_is_not_falsely_undeclared() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname=\"t\"\nversion=\"0.1\"\ndependencies=[\"requests\"]\n\n\
             [dependency-groups]\ndev = [\"pytest\", \"ruff\"]\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("tests")).unwrap();
        std::fs::write(
            dir.path().join("tests").join("test_demo.py"),
            "import pytest\n",
        )
        .unwrap();

        let result = analyze(dir.path());
        let undeclared: Vec<&str> = result
            .undeclared_imports
            .iter()
            .map(|u| u.package.as_str())
            .collect();
        assert!(
            !undeclared.contains(&"pytest"),
            "packages declared in [dependency-groups] must not be reported as \
             undeclared: {undeclared:?}"
        );
    }

    #[test]
    fn analyze_dependency_group_include_group_expansion_is_recognized() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname=\"t\"\nversion=\"0.1\"\ndependencies=[]\n\n\
             [dependency-groups]\n\
             dev = [\"pytest\"]\n\
             test = [{ include-group = \"dev\" }]\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("main.py"), "import pytest\n").unwrap();

        let result = analyze(dir.path());
        let undeclared: Vec<&str> = result
            .undeclared_imports
            .iter()
            .map(|u| u.package.as_str())
            .collect();
        assert!(
            !undeclared.contains(&"pytest"),
            "a dependency reachable only via PEP 735 include-group expansion \
             must still count as declared: {undeclared:?}"
        );
    }

    #[test]
    fn analyze_package_declared_in_two_groups_reports_both_scopes_when_unused() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname=\"t\"\nversion=\"0.1\"\ndependencies=[]\n\n\
             [dependency-groups]\n\
             dev = [\"pytest\"]\n\
             test = [\"pytest\"]\n",
        )
        .unwrap();
        // No .py files import pytest -- it stays unused in both groups.
        std::fs::write(dir.path().join("main.py"), "import requests\n").unwrap();

        let result = analyze(dir.path());
        let pytest_entry = result
            .unused_declarations
            .iter()
            .find(|u| u.package == "pytest")
            .expect("pytest should be reported as unused");
        assert_eq!(
            pytest_entry.declared_in.len(),
            2,
            "a package declared in two groups should list both scopes once each: {:?}",
            pytest_entry.declared_in
        );
        assert!(
            pytest_entry
                .declared_in
                .contains(&"dependency-groups.dev".to_string())
        );
        assert!(
            pytest_entry
                .declared_in
                .contains(&"dependency-groups.test".to_string())
        );
    }

    #[test]
    fn analyze_truly_undeclared_package_still_recommends_pybun_add() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname=\"t\"\nversion=\"0.1\"\ndependencies=[\"requests\"]\n\n\
             [project.optional-dependencies]\nml = [\"numpy\"]\n\n\
             [dependency-groups]\ndev = [\"pytest\"]\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("main.py"), "import flask\n").unwrap();

        let result = analyze(dir.path());
        let entry = result
            .undeclared_imports
            .iter()
            .find(|u| u.package == "flask")
            .expect("flask is genuinely undeclared in any recognized scope");
        assert_eq!(entry.next_action.tool, "pybun_add");
        assert_eq!(entry.next_action.args.get("package").unwrap(), "flask");
    }

    #[test]
    fn analyze_unused_declaration_reports_optional_dependency_scope() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname=\"t\"\nversion=\"0.1\"\ndependencies=[]\n\n\
             [project.optional-dependencies]\nml = [\"numpy\"]\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("main.py"), "# no imports\n").unwrap();

        let result = analyze(dir.path());
        let entry = result
            .unused_declarations
            .iter()
            .find(|u| u.package == "numpy")
            .expect("numpy should be reported as unused");
        assert_eq!(
            entry.declared_in,
            vec!["project.optional-dependencies.ml".to_string()]
        );
        assert_eq!(entry.next_action.tool, "pybun_remove");
    }
}
