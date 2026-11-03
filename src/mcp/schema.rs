//! MCP `tools/list` schema definitions.
//!
//! Extracted from `mcp.rs` (Issue #344): the tool name/description/input-schema
//! table returned by the `tools/list` JSON-RPC method. Preserves the exact
//! schema previously inlined in `handle_tools_list`.

use super::Tool;
use serde_json::json;

pub(super) fn build_tools_list() -> Vec<Tool> {
    let limits =
        serde_json::to_value(crate::security_assessment::ObservationLimits::default()).unwrap();
    let limit_properties: serde_json::Map<String, serde_json::Value> = limits
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, cap)| {
            (
                name.clone(),
                json!({"type":"integer","minimum":1,"maximum":cap}),
            )
        })
        .collect();
    let required_limits: Vec<_> = limit_properties.keys().cloned().collect();
    let mut tools = vec![
        Tool {
            name: "pybun_security_monitor".into(),
            description: "Explicit run-once security monitor registration, checks and durable local replay. Default denied; stored registrations confer no authority. No scheduler, external notification delivery, installation or resolution.".into(),
            input_schema: monitor_schema(),
        },
        Tool {
            name: "pybun_security_check".into(),
            description: "Read-only security update assessment of an explicitly granted, frozen operator profile. Does not install, resolve, update, or register a monitor. Default denied; requires compatible metadata/HTTP capabilities. Offline mode makes no provider requests.".into(),
            input_schema: json!({"type":"object","additionalProperties":false,"properties":{
                "profile":{"type":["string","null"],"description":"Operator-granted profile selector; unavailable profiles are not enumerated."},
                "project":{"type":["string","null"],"description":"Optional project selection; must match the frozen profile exactly."},
                "target":{"type":"string","enum":["installed","locked"],"default":"installed","description":"Locked inventory is currently an explicit unsupported result; never falls back."},
                "mode":{"type":"string","enum":["online","offline","online_with_cache_fallback"],"default":"online"},
                "limits":{"type":["object","null"],"additionalProperties":false,"properties":limit_properties,"required":required_limits},
                "max_cache_age_seconds":{"type":["integer","null"],"minimum":0},
                "fail_on":{"enum":["low","medium","high","critical",null]},
                "continuation":{"type":["string","null"],"maxLength":524288,"description":"Named assessment continuation, not a monitor event cursor."}
            }}),
        },
        Tool {
            name: "pybun_why".into(),
            description: "Explain every known path to a package from the active backend's frozen lock graph; does not resolve or sync. Reports conditional/extra/group/workspace and unknown provenance.".into(),
            input_schema: json!({"type":"object","properties":{"package":{"type":"string"}},"required":["package"],"additionalProperties":false}),
        },
        Tool {
            name: "pybun_environment_diff".into(),
            description: "Compare two captured environment states or receipts without mutation; distinguish unavailable evidence and never infer causality.".into(),
            input_schema: json!({"type":"object","properties":{"before":{"type":"object"},"after":{"type":"object"}},"required":["before","after"],"additionalProperties":false}),
        },
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
            description: "Synchronize the current uv project exactly, matching CLI install. Returns backend contract v2. Native requirements/index/system/binary-lock arguments require explicit PYBUN_BACKEND=native.".to_string(),
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
                        "description": "uv index URL or NAME=URL. Named-index credentials use UV_INDEX_<NAME>_USERNAME/PASSWORD; JSON fixture paths require native opt-in."
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
                        "description": "Request disabling the default MCP sandbox. Only takes effect if the server was started with `pybun mcp serve --allow-unsafe-no-sandbox`; otherwise this request is denied and the sandbox remains enabled."
                    },
                    "sandbox_policy": {
                        "type": "object",
                        "description": "Optional sandbox policy. MCP pybun_run is sandboxed by default; use unsafe_no_sandbox only for explicit opt-out.",
                        "properties": {
                            "allow_network": {
                                "type": "boolean",
                                "description": "Allow network access (default: false)"
                            },
                            "allow_net": {"type":"array", "items":{"type":"string"}, "description":"Allowed host[:port] destinations"},
                            "allow_run": {"type":"array", "items":{"type":"string"}, "description":"Trusted executable names or paths"},
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
                    },
                    "fix": {
                        "type": "boolean",
                        "description": "Preview shared safe remediation plan without applying changes"
                    },
                    "apply": {
                        "type": "boolean",
                        "description": "Apply low-risk auto-applicable fixes; requires fix=true. Returns before/after records."
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
                    "since": {
                        "type": "string",
                        "description": "Git base reference for changed=true (default HEAD)"
                    },
                    "changed": {
                        "type": "boolean",
                        "description": "Select affected tests from git changes and transitive AST imports; uncertain evidence selects all tests"
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
            description: "Update uv.lock with uv lock --upgrade/--upgrade-package, matching CLI upgrade; run install to sync afterward. Optional package/version retains audit next_action compatibility.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "packages": { "type": "array", "items": { "type": "string" } },
                    "index": { "type": "string", "description": "uv index URL or NAME=URL; authenticate via named-index environment variables." },
                    "offline": { "type": "boolean" },
                    "pre": { "type": "boolean" },
                    "package": {
                        "type": "string",
                        "description": "Package name to upgrade"
                    },
                    "version": {
                        "type": "string",
                        "description": "Target version (e.g. '2.31.0')"
                    }
                },
                "required": []
            }),
        },
    ];
    for operation in ["add", "remove", "lock"] {
        tools.push(Tool {
            name: format!("pybun_{operation}"),
            description: format!("uv-backed project {operation}; returns backend contract version 2, matching CLI semantics."),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "packages": { "type": "array", "items": { "type": "string" } },
                    "index": { "type": "string", "description": "uv index URL or NAME=URL; authenticate via named-index environment variables." },
                    "script": { "type": "string" },
                    "offline": { "type": "boolean" },
                    "pre": { "type": "boolean" }
                }
            }),
        });
    }
    tools
}

fn monitor_schema() -> serde_json::Value {
    let mut variants = vec![];
    for (action, required, fields) in [
        ("list", vec![], vec!["profile"]),
        (
            "add",
            vec!["name"],
            vec!["name", "profile", "project", "target"],
        ),
        (
            "check",
            vec!["monitor_id"],
            vec![
                "monitor_id",
                "after",
                "mode",
                "fail_on",
                "max_cache_age_seconds",
                "limits",
            ],
        ),
        ("events", vec!["monitor_id"], vec!["monitor_id", "after"]),
        (
            "configure",
            vec!["monitor_id", "expected_revision", "profile"],
            vec!["monitor_id", "expected_revision", "profile"],
        ),
        ("remove", vec!["monitor_id"], vec!["monitor_id"]),
    ] {
        let mut properties = serde_json::Map::new();
        properties.insert("action".into(), json!({"const":action}));
        properties.insert(
            "timeout_ms".into(),
            json!({"type":["integer","null"],"minimum":1,"maximum":60000}),
        );
        for field in fields {
            let schema = match field {
                "mode" => {
                    json!({"enum":["online","offline","online_with_cache_fallback"],"default":"online"})
                }
                "target" => json!({"enum":["installed","locked"],"default":"installed"}),
                "fail_on" => json!({"enum":["low","medium","high","critical",null]}),
                "expected_revision" => json!({"type":"integer","minimum":1}),
                "max_cache_age_seconds" => json!({"type":["integer","null"],"minimum":0}),
                "limits" => {
                    let limits = serde_json::to_value(
                        crate::security_assessment::ObservationLimits::default(),
                    )
                    .unwrap();
                    let fields: serde_json::Map<String, serde_json::Value> = limits
                        .as_object()
                        .unwrap()
                        .iter()
                        .map(|(name, cap)| {
                            (
                                name.clone(),
                                json!({"type":"integer","minimum":1,"maximum":cap}),
                            )
                        })
                        .collect();
                    let required: Vec<_> = fields.keys().cloned().collect();
                    json!({"type":["object","null"],"additionalProperties":false,"properties":fields,"required":required})
                }
                "after" => {
                    json!({"type":["string","null"],"maxLength":2048,"description":"Monitor event replay cursor, not assessment continuation."})
                }
                "name" => json!({"type":"string","minLength":1,"maxLength":200}),
                "profile" if action == "configure" => {
                    json!({"type":"string","description":"Must equal the monitor's stored configured profile binding."})
                }
                "profile" | "project" => {
                    json!({"type":["string","null"],"description":"Approved configured profile or exact matching project; never an authority grant."})
                }
                _ => json!({"type":"string","minLength":1,"maxLength":200}),
            };
            properties.insert(field.into(), schema);
        }
        let mut required = required;
        required.push("action");
        variants.push(json!({"type":"object","additionalProperties":false,"properties":properties,"required":required}));
    }
    json!({"oneOf":variants})
}
