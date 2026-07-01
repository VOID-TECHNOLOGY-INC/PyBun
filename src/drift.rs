//! Dependency drift detection via static import analysis.
//!
//! Phase 1: regex/token-based import scanning.
//! Cross-references Python `import` statements with `pyproject.toml` declarations.

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
    pub declared_in: String,
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
            for (line_no, line) in content.lines().enumerate() {
                let line = line.trim();
                if let Some(pkg) = parse_import_line(line) {
                    let loc = ImportLocation {
                        file: file_label.clone(),
                        line: line_no + 1,
                        statement: line.to_string(),
                    };
                    import_map.entry(pkg).or_default().push(loc);
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

    // Load declared dependencies from pyproject.toml (best-effort)
    let (declared_raw, declared_in) = if pyproject_path.exists() {
        match std::fs::read_to_string(&pyproject_path) {
            Ok(content) => {
                let names = parse_declared_deps(&content);
                (names, pyproject_path.to_string_lossy().to_string())
            }
            Err(_) => (vec![], pyproject_path.to_string_lossy().to_string()),
        }
    } else {
        (vec![], "pyproject.toml".to_string())
    };

    // Normalize declared names
    let declared_normalized: HashSet<String> = declared_raw
        .iter()
        .map(|d| normalize_package_name(&extract_package_name_from_dep(d)))
        .collect();

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
    let import_aliases_rev = import_aliases_reverse();
    let mut unused_declarations: Vec<UnusedDeclaration> = declared_raw
        .iter()
        .filter(|dep| {
            let name = normalize_package_name(&extract_package_name_from_dep(dep));
            // Check if this pypi name (or any of its import aliases) appears in imports
            let alt_import = import_aliases_rev.get(name.as_str());
            let is_used = resolved
                .values()
                .any(|(pypi, _)| normalize_package_name(pypi) == name)
                || alt_import.is_some_and(|aliases| {
                    aliases.iter().any(|alias| resolved.contains_key(*alias))
                });
            !is_used
        })
        .map(|dep| {
            let name = extract_package_name_from_dep(dep);
            let mut args = HashMap::new();
            args.insert("package".to_string(), name.clone());
            UnusedDeclaration {
                package: name,
                declared_in: declared_in.clone(),
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
    collect_py_files_inner(root, &mut files);
    files
}

fn collect_py_files_inner(dir: &Path, out: &mut Vec<PathBuf>) {
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
            "__pycache__" | ".venv" | "venv" | "env" | "node_modules" | "dist" | "build"
        ) {
            continue;
        }

        if path.is_dir() {
            collect_py_files_inner(&path, out);
        } else if path.extension().is_some_and(|e| e == "py") {
            out.push(path);
        }
    }
}

/// Parse a single Python source line and extract the top-level package name.
/// Returns `None` for non-import lines, comments, relative imports, and __future__.
pub fn parse_import_line(line: &str) -> Option<String> {
    let line = line.trim();

    // Skip comments and empty lines
    if line.starts_with('#') || line.is_empty() {
        return None;
    }

    // Skip relative imports (`from . import foo`, `from ..bar import baz`)
    // Skip `from __future__`
    if let Some(rest) = line.strip_prefix("from ") {
        let module = rest.split_whitespace().next()?;
        if module.starts_with('.') || module == "__future__" {
            return None;
        }
        // top-level package is the first component
        let top_level = module.split('.').next()?;
        return Some(top_level.to_string());
    }

    if let Some(rest) = line.strip_prefix("import ") {
        // Handle `import a, b, c` — take only the first package
        let first = rest.split(',').next()?.trim();
        // Handle `import a as alias`
        let module = first.split_whitespace().next()?;
        let top_level = module.split('.').next()?;
        return Some(top_level.to_string());
    }

    None
}

/// Normalize a package name for comparison (lowercase, hyphens→underscores).
fn normalize_package_name(name: &str) -> String {
    name.to_lowercase().replace('-', "_")
}

/// Extract bare package name from a PEP 508 dependency specifier.
fn extract_package_name_from_dep(dep: &str) -> String {
    dep.split(['>', '<', '=', '!', '[', ';', ' ', '\t'])
        .next()
        .unwrap_or(dep)
        .trim()
        .to_string()
}

/// Parse `[project.dependencies]` from pyproject.toml content.
fn parse_declared_deps(content: &str) -> Vec<String> {
    let Ok(value) = content.parse::<toml::Value>() else {
        return vec![];
    };
    value
        .get("project")
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
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
    m.insert("usaddress", "usaddress");
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
    m.insert("magic", "python-magic");
    m
}

/// Reverse mapping: PyPI name → list of possible import names.
fn import_aliases_reverse() -> HashMap<&'static str, Vec<&'static str>> {
    let mut m: HashMap<&'static str, Vec<&'static str>> = HashMap::new();
    for (import_name, pypi_name) in import_aliases() {
        m.entry(pypi_name).or_default().push(import_name);
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
}
