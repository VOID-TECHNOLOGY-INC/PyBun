//! MCP `tools/list` schema definitions.
//!
//! Extracted from `mcp.rs` (Issue #344): the tool name/description/input-schema
//! table returned by the `tools/list` JSON-RPC method. Preserves the exact
//! schema previously inlined in `handle_tools_list`.

use super::Tool;
use serde_json::json;

pub(super) fn build_tools_list() -> Vec<Tool> {
    let tools = vec![
        Tool {
            name: "pybun_resolve".to_string(),
            description: "Resolve Python package dependencies".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "requirements": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of requirements (e.g., ['requests>=2.28', 'flask'])"
                    },
                    "pre": {
                        "type": "boolean",
                        "description": "Allow pre-release and dev versions when resolving (PEP 440 excludes them by default unless a specifier mentions one; default: false)"
                    }
                },
                "required": ["requirements"]
            }),
        },
        Tool {
            name: "pybun_install".to_string(),
            description: "Install Python packages. Delegates to the same real install path as CLI `pybun install`: resolves dependencies (falling back to PyPI when no `index` is given), verifies real sha256 hashes, downloads wheels, and installs them into the target environment. Reports \"installed\" only when wheels were actually downloaded and installed; otherwise reports an honest \"resolved\" status.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "requirements": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of requirements to install. If omitted, dependencies are read from pyproject.toml."
                    },
                    "offline": {
                        "type": "boolean",
                        "description": "Use offline mode (cache only); honored by the underlying install path"
                    },
                    "system": {
                        "type": "boolean",
                        "description": "Allow installing into system Python instead of creating a project-local .pybun/venv (default: false)"
                    },
                    "pre": {
                        "type": "boolean",
                        "description": "Allow pre-release and dev versions when resolving (PEP 440 excludes them by default unless a specifier mentions one; default: false)"
                    },
                    "index": {
                        "type": "string",
                        "description": "Path to a local index JSON file. If omitted, falls back to PyPI (same as the CLI)."
                    },
                    "lock": {
                        "type": "string",
                        "description": "Path to write the lockfile (default: pybun.lockb)"
                    }
                }
            }),
        },
        Tool {
            name: "pybun_run".to_string(),
            description: "Run a Python script inside the default MCP sandbox unless explicitly opted out.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "script": {
                        "type": "string",
                        "description": "Path to the Python script"
                    },
                    "code": {
                        "type": "string",
                        "description": "Inline Python code to execute"
                    },
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Arguments to pass to the script"
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "Return an execution plan and risk summary without running code"
                    },
                    "unsafe_no_sandbox": {
                        "type": "boolean",
                        "description": "Disable the default MCP sandbox. Use only in controlled environments."
                    },
                    "sandbox_policy": {
                        "type": "object",
                        "description": "Optional sandbox policy. MCP pybun_run is sandboxed by default; use unsafe_no_sandbox only for explicit opt-out.",
                        "properties": {
                            "allow_network": {
                                "type": "boolean",
                                "description": "Allow network access (default: false)"
                            },
                            "allow_read": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Paths allowed for reading (empty = no restriction)"
                            },
                            "allow_write": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Paths allowed for writing (empty = no restriction)"
                            },
                            "allow_env": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Additional non-secret environment variable names to pass through"
                            },
                            "timeout_secs": {
                                "type": "integer",
                                "description": "Maximum wall-clock execution time in seconds"
                            }
                        }
                    }
                }
            }),
        },
        Tool {
            name: "pybun_gc".to_string(),
            description: "Run garbage collection on PyBun cache".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "max_size": {
                        "type": "string",
                        "description": "Maximum cache size (e.g., '1G', '500M')"
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "Preview without deleting"
                    }
                }
            }),
        },
        Tool {
            name: "pybun_doctor".to_string(),
            description: "Run environment diagnostics".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "verbose": {
                        "type": "boolean",
                        "description": "Include verbose diagnostics"
                    }
                }
            }),
        },
        Tool {
            name: "pybun_lint".to_string(),
            description: "Run linting on Python code and return structured violations. Uses ruff if available.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "script": {
                        "type": "string",
                        "description": "Path to Python file or directory to lint"
                    },
                    "code": {
                        "type": "string",
                        "description": "Inline Python code to lint (written to a temp file)"
                    },
                    "select": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Rule codes to enable (e.g. ['E501', 'F401'])"
                    }
                }
            }),
        },
        Tool {
            name: "pybun_type_check".to_string(),
            description: "Run type checking on Python code using mypy. Returns structured type errors with hints.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "script": {
                        "type": "string",
                        "description": "Path to Python file or directory to type-check"
                    },
                    "code": {
                        "type": "string",
                        "description": "Inline Python code to type-check"
                    },
                    "strict": {
                        "type": "boolean",
                        "description": "Enable strict mypy mode"
                    }
                }
            }),
        },
        Tool {
            name: "pybun_profile".to_string(),
            description: "Profile a Python script using cProfile and return performance hotspots.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "script": {
                        "type": "string",
                        "description": "Path to Python script to profile"
                    },
                    "code": {
                        "type": "string",
                        "description": "Inline Python code to profile"
                    },
                    "top_n": {
                        "type": "integer",
                        "description": "Number of top hotspots to return (default: 10)"
                    }
                }
            }),
        },
        Tool {
            name: "pybun_fix".to_string(),
            description: "Auto-fix lint violations in a Python file using ruff. Returns a summary of applied fixes.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "script": {
                        "type": "string",
                        "description": "Path to Python file to fix (required)"
                    },
                    "select": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Rule codes to fix (default: all auto-fixable)"
                    },
                    "unsafe_fixes": {
                        "type": "boolean",
                        "description": "Apply unsafe fixes (default: false)"
                    }
                },
                "required": ["script"]
            }),
        },
        Tool {
            name: "pybun_context".to_string(),
            description: "Return a single-call project state snapshot for agent consumption. Aggregates Python version, venv status, lockfile status, installed packages, and doctor warnings into one structured response.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "summary_only": {
                        "type": "boolean",
                        "description": "Return package counts instead of the full installed_packages list (reduces output size for low-token contexts)"
                    },
                    "include_drift": {
                        "type": "boolean",
                        "description": "Include AST-based import drift analysis (reserved for future use; currently returns null)"
                    }
                }
            }),
        },
        Tool {
            name: "pybun_test".to_string(),
            description: "Run Python tests and return structured per-test results. Returns summary, failures (with rerun_command), and passed entries for agent-friendly test workflows.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Test file or directory to run (default: auto-discover from current directory)"
                    },
                    "changed": {
                        "type": "boolean",
                        "description": "Run only tests in files changed since last git commit (new untracked test files are also included)"
                    },
                    "fail_fast": {
                        "type": "boolean",
                        "description": "Stop on first failure"
                    },
                    "filter": {
                        "type": "string",
                        "description": "Test name pattern filter (runs only tests whose name contains this string)"
                    }
                }
            }),
        },
        Tool {
            name: "pybun_drift".to_string(),
            description: "Detect dependency drift: undeclared imports (packages imported but not in pyproject.toml) and unused declarations (packages in pyproject.toml but never imported). Returns structured results with agent-callable next_action for pybun_add/pybun_remove.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "cwd": {
                        "type": "string",
                        "description": "Directory to analyze (defaults to current working directory)"
                    }
                }
            }),
        },
        Tool {
            name: "pybun_audit".to_string(),
            description: "Scan installed packages for known vulnerabilities using the OSV database. Returns structured results with severity levels and agent-callable fix suggestions via next_action.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "fix": {
                        "type": "boolean",
                        "description": "Populate next_action with the pybun_upgrade call needed to fix each vulnerability (default: true)"
                    },
                    "severity_threshold": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "critical"],
                        "description": "Only report vulnerabilities at or above this severity level (default: low)"
                    }
                }
            }),
        },
        Tool {
            name: "pybun_upgrade".to_string(),
            description: "Upgrade a single package to a specific version in the current environment. Intended to be called by agents acting on next_action entries from pybun_audit.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "package": {
                        "type": "string",
                        "description": "Package name to upgrade"
                    },
                    "version": {
                        "type": "string",
                        "description": "Target version (e.g. '2.31.0')"
                    }
                },
                "required": ["package", "version"]
            }),
        },
    ];
    tools
}
