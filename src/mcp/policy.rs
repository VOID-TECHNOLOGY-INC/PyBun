//! Frozen operator policy. Authorization precedes snapshots, audit setup and tools.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs::OpenOptions;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Policy {
    #[serde(skip)]
    pub rate_limit: super::rate_limit::Config,
    pub default_sandbox: bool,
    pub require_sandbox: bool,
    pub allow_network: bool,
    pub max_execution_time_s: u64,
    pub max_memory_mb: u64,
    pub max_cpu_time_s: u64,
    pub denied_tools: Vec<String>,
    pub allowed_working_directories: Vec<PathBuf>,
    pub allowed_backends: Vec<String>,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            rate_limit: super::rate_limit::Config::default(),
            default_sandbox: true,
            require_sandbox: true,
            allow_network: false,
            max_execution_time_s: 60,
            max_memory_mb: 0,
            max_cpu_time_s: 0,
            denied_tools: vec![],
            allowed_working_directories: vec![PathBuf::from(".")],
            allowed_backends: vec!["uv".into(), "native".into()],
        }
    }
}
#[derive(Clone, Debug)]
pub(super) struct Denied(pub &'static str, pub &'static str);
impl Denied {
    pub fn value(&self) -> Value {
        json!({"contract_version":"2","status":"error","policy_applied":{"authorized":false},"diagnostics":[{"level":"error","code":self.0,"message":self.1}]})
    }
}
fn invalid() -> Denied {
    Denied(
        "E_MCP_POLICY_INVALID",
        "Server security policy is invalid or unreadable; ask the operator to correct it.",
    )
}
fn capability() -> Denied {
    Denied(
        "E_MCP_POLICY_UNSUPPORTED",
        "This tool cannot enforce the configured sandbox, network or resource boundary; use a compatible tool or ask the operator to configure its capabilities.",
    )
}

// Authorization runs before rate admission, so this probe must be bounded and
// must never wait for a FIFO/device or read a file that grows past the limit.
fn preparation_source(path: &Path) -> Result<String, Denied> {
    const LIMIT: u64 = 2 * 1024 * 1024;
    let metadata = std::fs::symlink_metadata(path).map_err(|_| invalid())?;
    if !metadata.is_file() || metadata.len() > LIMIT {
        return Err(capability());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|_| invalid())?;
    if !file.metadata().map_err(|_| invalid())?.is_file() {
        return Err(capability());
    }
    let mut bytes = Vec::new();
    file.take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    if bytes.len() as u64 > LIMIT {
        return Err(capability());
    }
    String::from_utf8(bytes).map_err(|_| invalid())
}

pub(super) struct ServerPolicy {
    pub root: PathBuf,
    pub effective: Result<Policy, Denied>,
}
impl ServerPolicy {
    pub fn load(root: &Path, override_path: Option<&Path>) -> Self {
        let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let effective = Self::read(&root, override_path);
        Self { root, effective }
    }
    fn read(root: &Path, override_path: Option<&Path>) -> Result<Policy, Denied> {
        let local = root.join(".pybun/config.toml");
        let path = override_path.map(PathBuf::from).unwrap_or_else(|| {
            if local.exists() {
                local
            } else {
                root.join("pyproject.toml")
            }
        });
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options.open(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound { Denied("E_MCP_POLICY_MISSING", "Protected tools require an operator-owned MCP policy configured before server startup.") } else { invalid() }
        })?;
        if !file.metadata().map_err(|_| invalid())?.is_file() {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        file.take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid())?;
        if bytes.len() > 1024 * 1024 {
            return Err(invalid());
        }
        let value: toml::Value =
            toml::from_str(std::str::from_utf8(&bytes).map_err(|_| invalid())?)
                .map_err(|_| invalid())?;
        let section = value
            .get("tool")
            .and_then(|v| v.get("pybun"))
            .and_then(|v| v.get("mcp"))
            .or_else(|| value.get("mcp"));
        let mut policy: Policy = section
            .and_then(|v| v.get("policy"))
            .ok_or(Denied(
                "E_MCP_POLICY_MISSING",
                "Protected tools require an operator-owned MCP policy section.",
            ))?
            .clone()
            .try_into()
            .map_err(|_| invalid())?;
        if let Some(rates) = section.and_then(|value| value.get("rate_limit")) {
            policy.rate_limit = rates.clone().try_into().map_err(|_| invalid())?;
        }
        let tools: Vec<_> = super::schema::build_tools_list()
            .into_iter()
            .map(|tool| tool.name)
            .collect();
        if !policy.rate_limit.validate(&tools) {
            return Err(invalid());
        }
        if policy.allowed_working_directories.is_empty()
            || policy
                .allowed_backends
                .iter()
                .any(|v| !matches!(v.as_str(), "uv" | "native"))
            || policy.max_execution_time_s > 86400
            || policy.max_cpu_time_s > 86400
            || policy.max_memory_mb > 1048576
        {
            return Err(invalid());
        }
        for directory in &mut policy.allowed_working_directories {
            *directory = root
                .join(&*directory)
                .canonicalize()
                .map_err(|_| invalid())?;
        }
        Ok(policy)
    }
    pub fn denial_value(&self, denied: &Denied) -> Value {
        let mut value = denied.value();
        if let Ok(policy) = &self.effective {
            value["policy_applied"] = serde_json::to_value(policy).unwrap();
            value["policy_applied"]["authorized"] = json!(false);
        }
        crate::support_bundle::redact_json(&value)
    }
    fn path(&self, policy: &Policy, value: &str) -> Result<(), Denied> {
        let deny = || {
            Denied(
                "E_MCP_POLICY_PATH_DENIED",
                "A requested path is outside the operator's working-directory boundary.",
            )
        };
        let path = Path::new(value);
        if path.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(deny());
        }
        let mut candidate = self.root.join(path);
        // Missing output paths are checked through their closest existing ancestor.
        loop {
            match std::fs::symlink_metadata(&candidate) {
                Ok(_) => break,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if !candidate.pop() {
                        return Err(deny());
                    }
                }
                Err(_) => return Err(deny()),
            }
        }
        let canonical = candidate.canonicalize().map_err(|_| deny())?;
        if !policy
            .allowed_working_directories
            .iter()
            .any(|root| canonical.starts_with(root))
        {
            return Err(deny());
        }
        Ok(())
    }
    pub fn authorize(
        &self,
        tool: &str,
        mut args: Value,
        backend: &str,
    ) -> Result<Authorized, Denied> {
        // Pure in-memory comparisons do not require execution privileges.
        if tool == "pybun_environment_diff" && self.effective.is_err() {
            return Ok(Authorized {
                args,
                applied: json!({"authorized":true,"scope":"in_memory_only"}),
            });
        }
        let policy = self.effective.as_ref().map_err(Clone::clone)?;
        if !args.is_object() {
            return Err(Denied(
                "E_MCP_POLICY_ARGUMENT",
                "Tool arguments must be an object.",
            ));
        }
        if policy.denied_tools.iter().any(|name| name == tool) {
            return Err(Denied(
                "E_MCP_POLICY_TOOL_DENIED",
                "This tool is denied by the server operator.",
            ));
        }
        let cwd = std::env::current_dir().map_err(|_| invalid())?;
        self.path(policy, cwd.to_str().ok_or_else(invalid)?)?;
        for ancestor in self.root.ancestors().skip(1) {
            if ancestor.join("pyproject.toml").is_file() {
                self.path(policy, ancestor.to_str().ok_or_else(invalid)?)?;
            }
        }
        for output in [
            "pyproject.toml",
            "uv.lock",
            "pybun.lockb",
            ".venv",
            ".pybun/venv",
            ".pybun/receipts",
        ] {
            self.path(policy, output)?;
        }
        if backend == "uv" {
            for name in [
                "UV_PROJECT_ENVIRONMENT",
                "UV_PROJECT",
                "UV_WORKING_DIRECTORY",
            ] {
                if let Some(path) = std::env::var_os(name) {
                    self.path(policy, path.to_str().ok_or_else(invalid)?)?;
                }
            }
        }
        for key in ["cwd", "script", "path", "lock"] {
            if let Some(value) = args.get(key) {
                self.path(policy, value.as_str().ok_or_else(invalid)?)?;
            }
        }
        if let Some(script) = args["script"].as_str() {
            self.path(policy, &format!("{script}.lock"))?;
        }
        for key in ["packages", "requirements"] {
            if let Some(values) = args.get(key) {
                for value in values.as_array().ok_or_else(invalid)? {
                    if value
                        .as_str()
                        .is_none_or(|value| value.trim_start().starts_with('-'))
                    {
                        return Err(Denied(
                            "E_MCP_POLICY_ARGUMENT",
                            "Package arguments cannot contain option flags.",
                        ));
                    }
                }
            }
        }
        if args["package"]
            .as_str()
            .is_some_and(|value| value.trim_start().starts_with('-'))
        {
            return Err(Denied(
                "E_MCP_POLICY_ARGUMENT",
                "Package arguments cannot contain option flags.",
            ));
        }
        if args.get("system").and_then(Value::as_bool) == Some(true) {
            return Err(Denied(
                "E_MCP_POLICY_PATH_DENIED",
                "System-environment mutation is unavailable through the protected server.",
            ));
        }
        if [
            "pybun_run",
            "pybun_install",
            "pybun_resolve",
            "pybun_add",
            "pybun_remove",
            "pybun_lock",
            "pybun_upgrade",
            "pybun_why",
        ]
        .contains(&tool)
            && !policy.allowed_backends.iter().any(|name| name == backend)
        {
            return Err(Denied(
                "E_MCP_POLICY_BACKEND_DENIED",
                "The selected backend is not allowed by the server operator.",
            ));
        }
        let mut applied = serde_json::to_value(policy).map_err(|_| invalid())?;
        applied["authorized"] = json!(true);
        if tool == "pybun_run" {
            let sandboxed = policy.require_sandbox
                || policy.default_sandbox
                || !policy.allow_network
                || policy.max_execution_time_s > 0
                || policy.max_memory_mb > 0
                || policy.max_cpu_time_s > 0
                || args["unsafe_no_sandbox"] != true;
            if sandboxed {
                args["unsafe_no_sandbox"] = json!(false);
            }
            if policy.max_memory_mb > 0 && !cfg!(all(unix, not(target_os = "macos"))) {
                return Err(capability());
            }
            if policy.max_cpu_time_s > 0 && !cfg!(unix) {
                return Err(capability());
            }
            let bounded = policy.max_execution_time_s > 0
                || policy.max_memory_mb > 0
                || policy.max_cpu_time_s > 0;
            let preview = args["dry_run"] == true;
            if backend == "uv" && bounded && preview {
                applied["execution_supported"] = json!(false);
                applied["execution_denial_code"] = json!("E_MCP_POLICY_UNSUPPORTED");
            }
            if backend == "uv" && bounded && !preview {
                return Err(capability());
            }
            if backend == "native" && (!policy.allow_network || bounded) && !preview {
                let code = if let Some(script) = args["script"].as_str() {
                    let path = self.root.join(script);
                    match std::fs::symlink_metadata(self.root.join(format!("{script}.lock"))) {
                        Ok(_) => return Err(capability()),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(_) => return Err(invalid()),
                    }
                    preparation_source(&path)?
                } else {
                    args["code"].as_str().unwrap_or("").to_string()
                };
                if code.contains("# /// script") {
                    return Err(capability());
                }
            }
            let mut sandbox = args
                .get("sandbox_policy")
                .cloned()
                .unwrap_or_else(|| json!({}));
            if !sandbox.is_object() {
                return Err(invalid());
            }
            if !policy.allow_network {
                sandbox["allow_network"] = json!(false);
                sandbox["allow_net"] = json!([]);
                sandbox["allow_run"] = json!([]);
            }
            for (key, cap) in [
                ("timeout_secs", policy.max_execution_time_s),
                ("memory_limit_mb", policy.max_memory_mb),
                ("cpu_limit_secs", policy.max_cpu_time_s),
            ] {
                let requested = sandbox
                    .get(key)
                    .map(|v| v.as_u64().ok_or_else(invalid))
                    .transpose()?
                    .unwrap_or(if key == "timeout_secs" { 60 } else { 0 });
                sandbox[key] = json!(if cap == 0 {
                    requested
                } else if requested == 0 {
                    cap
                } else {
                    cap.min(requested)
                });
            }
            if sandboxed {
                for key in ["allow_read", "allow_write"] {
                    let values = sandbox
                        .get(key)
                        .map(|v| v.as_array().ok_or_else(invalid))
                        .transpose()?;
                    if let Some(values) = values {
                        for value in values {
                            self.path(policy, value.as_str().ok_or_else(invalid)?)?;
                        }
                    }
                    if values.is_none_or(Vec::is_empty) {
                        sandbox[key] = json!([self.root]);
                    }
                }
            }
            applied["sandboxed"] = json!(sandboxed);
            applied["sandbox_policy"] = sandbox.clone();
            args["sandbox_policy"] = sandbox;
        } else if !matches!(tool, "pybun_environment_diff" | "pybun_gc" | "pybun_drift")
            && (policy.require_sandbox
                || !policy.allow_network
                || policy.max_memory_mb > 0
                || policy.max_cpu_time_s > 0
                || policy.max_execution_time_s > 0)
        {
            // Other handlers do not yet propagate these runtime capabilities.
            // Deny rather than return an enforcement claim they cannot satisfy.
            return Err(capability());
        }
        args["_authorized_roots"] = json!(policy.allowed_working_directories);
        Ok(Authorized { args, applied })
    }
}
pub(super) struct Authorized {
    pub args: Value,
    pub applied: Value,
}
impl Authorized {
    pub fn decorate(&self, result: Result<String, String>) -> Result<String, String> {
        let decorate = |text: String| {
            if let Ok(mut value) = serde_json::from_str::<Value>(&text)
                && value.is_object()
            {
                value["policy_applied"] = self.applied.clone();
                if value["code"]
                    .as_str()
                    .is_some_and(|code| code.starts_with("E_MCP_POLICY_"))
                {
                    value["policy_applied"]["authorized"] = json!(false);
                }
                value.to_string()
            } else {
                text
            }
        };
        result.map(decorate).map_err(|text| {
            if serde_json::from_str::<Value>(&text).is_ok() { decorate(text) }
            else { json!({"contract_version":"2","status":"error","policy_applied":self.applied,"diagnostics":[{"level":"error","code":"E_MCP_TOOL_FAILED","message":crate::support_bundle::redact_response(&text)}]}).to_string() }
        })
    }
}

pub(crate) fn authorized_roots(args: &Value) -> Vec<PathBuf> {
    args["_authorized_roots"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(PathBuf::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_preparation_is_rejected_when_it_cannot_be_enforced() {
        let root = std::env::current_dir().unwrap().canonicalize().unwrap();
        let policy = ServerPolicy {
            root: root.clone(),
            effective: Ok(Policy {
                allow_network: true,
                allowed_working_directories: vec![root],
                ..Default::default()
            }),
        };
        assert!(
            policy
                .authorize("pybun_run", json!({"code":"print(1)"}), "uv")
                .is_err()
        );
        assert!(
            policy
                .authorize(
                    "pybun_run",
                    json!({"code":"# /// script\n# dependencies = ['demo']\n# ///\nprint(1)"}),
                    "native"
                )
                .is_err()
        );
    }
    #[test]
    fn configuration_precedence_and_freezing_are_explicit() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("pyproject.toml"),
            "[tool.pybun.mcp.policy]\nallow_network=true\n[tool.pybun.mcp.rate_limit]\ncalls_per_minute=1\n",
        )
        .unwrap();
        let original = ServerPolicy::load(temp.path(), None);
        std::fs::create_dir(temp.path().join(".pybun")).unwrap();
        std::fs::write(
            temp.path().join(".pybun/config.toml"),
            "[mcp.policy]\nallow_network=false\n[mcp.rate_limit]\ncalls_per_minute=2\n",
        )
        .unwrap();
        assert_eq!(
            original
                .effective
                .as_ref()
                .unwrap()
                .rate_limit
                .calls_per_minute,
            1
        );
        assert_eq!(
            ServerPolicy::load(temp.path(), None)
                .effective
                .unwrap()
                .rate_limit
                .calls_per_minute,
            2
        );
        assert!(original.effective.unwrap().allow_network);
        assert!(
            !ServerPolicy::load(temp.path(), None)
                .effective
                .unwrap()
                .allow_network
        );
        assert!(
            ServerPolicy::load(temp.path(), Some(&temp.path().join("pyproject.toml")))
                .effective
                .unwrap()
                .allow_network
        );
        std::fs::write(
            temp.path().join(".pybun/config.toml"),
            "[mcp.policy]\nallow_network='authenticated-secret'\n",
        )
        .unwrap();
        let denied = ServerPolicy::load(temp.path(), None).effective.unwrap_err();
        assert_eq!(denied.0, "E_MCP_POLICY_INVALID");
        assert!(!denied.value().to_string().contains("authenticated-secret"));
    }
    #[test]
    fn every_advertised_tool_obeys_operator_denial() {
        let root = std::env::current_dir().unwrap();
        let tools = super::super::schema::build_tools_list();
        let names = tools.iter().map(|tool| tool.name.clone()).collect();
        let server = ServerPolicy {
            root: root.clone(),
            effective: Ok(Policy {
                denied_tools: names,
                allowed_working_directories: vec![root],
                ..Default::default()
            }),
        };
        for tool in tools {
            assert_eq!(
                server
                    .authorize(&tool.name, json!({}), "native")
                    .err()
                    .unwrap()
                    .0,
                "E_MCP_POLICY_TOOL_DENIED"
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn missing_outputs_and_symlinks_stay_within_authorized_roots() {
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), temp.path().join("escape")).unwrap();
        let root = temp.path().canonicalize().unwrap();
        let policy = Policy {
            allowed_working_directories: vec![root.clone()],
            ..Default::default()
        };
        let server = ServerPolicy {
            root,
            effective: Ok(policy.clone()),
        };
        assert!(server.path(&policy, "new/output/file").is_ok());
        assert!(server.path(&policy, "escape/new/file").is_err());
        assert!(server.path(&policy, "../outside").is_err());
    }
    #[test]
    fn flag_like_package_arguments_cannot_inject_typed_paths() {
        let root = std::env::current_dir().unwrap().canonicalize().unwrap();
        let server = ServerPolicy {
            root: root.clone(),
            effective: Ok(Policy {
                require_sandbox: false,
                default_sandbox: false,
                allow_network: true,
                max_execution_time_s: 0,
                allowed_working_directories: vec![root],
                ..Default::default()
            }),
        };
        assert!(
            server
                .authorize(
                    "pybun_lock",
                    json!({"packages":["--script","/outside/script.py"]}),
                    "uv"
                )
                .is_err()
        );
    }
    #[cfg(unix)]
    #[test]
    fn dangling_output_symlinks_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path().join("future"), temp.path().join("uv.lock"))
            .unwrap();
        let root = temp.path().canonicalize().unwrap();
        let policy = Policy {
            allowed_working_directories: vec![root.clone()],
            ..Default::default()
        };
        let server = ServerPolicy {
            root,
            effective: Ok(policy.clone()),
        };
        assert!(server.path(&policy, "uv.lock").is_err());
    }
    #[test]
    fn policy_deserializes_defaults() {
        let value: toml::Value = toml::from_str("denied_tools=['pybun_gc']").unwrap();
        let policy: Policy = value.try_into().unwrap();
        assert_eq!(policy.denied_tools, vec!["pybun_gc"]);
    }
}
