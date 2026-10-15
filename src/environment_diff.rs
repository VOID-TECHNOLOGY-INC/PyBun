//! Read-only comparison of captured environment evidence, shared by CLI/MCP.
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const FIELDS: &[(&str, &[&str])] = &[
    (
        "python",
        &[
            "implementation",
            "version",
            "abi",
            "executable",
            "executable_digest",
        ],
    ),
    ("backend", &["name", "version"]),
    ("lock", &["source", "digest"]),
    ("project", &["path", "workspace"]),
    (
        "profile",
        &["name", "optimization_level", "lazy_imports", "timing"],
    ),
    (
        "configuration",
        &["python_requirement", "dependency_groups", "extras"],
    ),
    (
        "effective_policy",
        &[
            "sandboxed",
            "enabled",
            "allow_network",
            "allow_net",
            "allow_run",
            "timeout_secs",
            "memory_limit_mb",
            "cpu_limit_secs",
            "max_processes",
            "file_size_limit_mb",
            "enforcement",
            "max_execution_time_s",
            "max_memory_mb",
            "working_directory",
            "denied_tools",
            "backend_timeout_secs",
            "native_fallback",
            "allow_read",
            "allow_write",
            "allow_env",
            "default_deny_write",
        ],
    ),
    (
        "effective_policy.resource_limits",
        &[
            "timeout_secs",
            "memory_limit_mb",
            "cpu_limit_secs",
            "max_processes",
            "file_size_limit_mb",
            "unsupported",
        ],
    ),
];

pub fn read(path: &Path) -> Result<Value, String> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|_| "Cannot open environment record")?;
    if !file
        .metadata()
        .map_err(|_| "Cannot inspect environment record")?
        .is_file()
    {
        return Err("Environment record must be a regular JSON file".into());
    }
    let mut bytes = Vec::new();
    file.take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read environment record")?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("Environment record exceeds 4 MiB".into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "Environment record is not valid JSON".into())
}

fn state(input: &Value) -> Result<&Value, String> {
    let value = input
        .get("state")
        .or_else(|| input.get("detail"))
        .unwrap_or(input);
    if !value.is_object() {
        return Err("Environment evidence must be a JSON object".into());
    }
    if value
        .get("schema_version")
        .is_some_and(|version| version != 1)
    {
        return Err("Unsupported environment record schema version".into());
    }
    Ok(value)
}

fn field_value(input: &Value, section: &str, key: &str) -> Result<Value, String> {
    let section_value = section.split('.').fold(input, |value, key| &value[key]);
    let raw = if section == "python" && key == "executable" && section_value[key].is_null() {
        &input["environment"]["python"]
    } else {
        &section_value[key]
    };
    let list = matches!(
        key,
        "workspace"
            | "unsupported"
            | "dependency_groups"
            | "extras"
            | "allow_net"
            | "allow_run"
            | "denied_tools"
            | "allow_read"
            | "allow_write"
            | "allow_env"
    );
    let boolean = matches!(
        key,
        "sandboxed"
            | "enabled"
            | "allow_network"
            | "native_fallback"
            | "default_deny_write"
            | "lazy_imports"
            | "timing"
    );
    let number = matches!(
        key,
        "optimization_level"
            | "max_processes"
            | "file_size_limit_mb"
            | "timeout_secs"
            | "memory_limit_mb"
            | "cpu_limit_secs"
            | "max_execution_time_s"
            | "max_memory_mb"
            | "backend_timeout_secs"
    );
    let valid = raw.is_null()
        || if list {
            raw.as_array()
                .is_some_and(|items| items.iter().all(Value::is_string))
        } else if boolean {
            raw.is_boolean()
        } else if number {
            raw.is_u64()
        } else {
            raw.is_string()
        };
    if !valid {
        return Err("Environment evidence has an invalid field type".into());
    }
    let mut value = safe(raw);
    if list && let Some(items) = value.as_array_mut() {
        items.sort_by_key(Value::to_string);
        items.dedup();
    }
    Ok(value)
}

fn safe(value: &Value) -> Value {
    // Apply the normal redactor before comparison: masked values cannot prove
    // equality or a value change. Never copy unrestricted environment contents.
    crate::support_bundle::redact_protocol(value)
}
fn known(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(text) => {
            !text.is_empty()
                && !text.contains("<redacted>")
                && !matches!(
                    text.to_ascii_lowercase().as_str(),
                    "unknown" | "unavailable"
                )
        }
        Value::Array(items) => items.iter().all(known),
        Value::Object(map) => map.values().all(known),
        _ => true,
    }
}
fn evidence(unavailable: &mut Vec<Value>, field: &str, before: &Value, after: &Value) {
    unavailable.push(json!({"field":field,"reason_code":"ENV_EVIDENCE_UNAVAILABLE","before_available":known(before),"after_available":known(after)}));
}
fn change(changes: &mut Vec<Value>, field: &str, reason: &str, before: Value, after: Value) {
    changes.push(json!({"field":field,"reason_code":reason,"change":if before.is_null(){"added"}else if after.is_null(){"removed"}else{"changed"},"before":before,"after":after}));
}

fn packages(value: &Value, qualified: bool) -> Result<Option<BTreeMap<String, Value>>, String> {
    let mut result = BTreeMap::new();
    for package in value
        .as_array()
        .ok_or("Package evidence must be an array")?
    {
        let name = package
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| {
                !name.is_empty()
                    && name
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || "-_.".contains(ch))
            })
            .ok_or("Package evidence has no valid name")?;
        let name = name
            .split(['-', '_', '.'])
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join("-")
            .to_ascii_lowercase();
        if name.is_empty() {
            return Err("Package evidence has no valid name".into());
        }
        if !known(&safe(&json!(package["name"]))) || !known(&safe(&json!(name))) {
            return Ok(None);
        }
        let version = package.get("version").cloned().unwrap_or(Value::Null);
        if !version.is_null() && !version.is_string() {
            return Err("Package version evidence must be a string".into());
        }
        if qualified && !known(&safe(&version)) {
            return Ok(None);
        }
        let mut normalized = Map::new();
        normalized.insert("version".into(), safe(&version));
        if let Some(hashes) = package
            .get("artifact_hashes")
            .filter(|value| !value.is_null())
        {
            let mut hashes = hashes
                .as_array()
                .filter(|items| items.iter().all(Value::is_string))
                .cloned()
                .ok_or("Artifact hashes must be a string array")?;
            hashes.sort_by_key(Value::to_string);
            hashes.dedup();
            normalized.insert("artifact_hashes".into(), safe(&json!(hashes)));
        }
        let package = Value::Object(normalized);
        let key = if qualified {
            format!("{name}@{}", version.as_str().unwrap_or("unknown"))
        } else {
            name
        };
        if let Some(previous) = result.insert(key, package.clone())
            && (!qualified || previous != package)
        {
            return Err("Package evidence has ambiguous duplicate names".into());
        }
    }
    Ok(Some(result))
}

pub fn compare(before: &Value, after: &Value) -> Result<Value, String> {
    let before = state(before)?;
    let after = state(after)?;
    let mut changes = Vec::new();
    let mut unavailable = Vec::new();
    for (section, keys) in FIELDS {
        for key in *keys {
            let field = format!("{section}.{key}");
            let left = field_value(before, section, key)?;
            let right = field_value(after, section, key)?;
            if !known(&left) || !known(&right) {
                evidence(&mut unavailable, &field, &left, &right);
            } else if left != right {
                change(
                    &mut changes,
                    &field,
                    &format!(
                        "{}_CHANGED",
                        section.split('.').next().unwrap().to_ascii_uppercase()
                    ),
                    left,
                    right,
                );
            }
        }
    }
    for inventory in ["installed_packages", "packages"] {
        let left = &before[inventory];
        let right = &after[inventory];
        if left.is_null() || right.is_null() {
            evidence(&mut unavailable, inventory, left, right);
            continue;
        }
        let left = packages(left, inventory == "packages")?;
        let right = packages(right, inventory == "packages")?;
        let availability_left = if left.is_some() {
            json!([])
        } else {
            Value::Null
        };
        let availability_right = if right.is_some() {
            json!([])
        } else {
            Value::Null
        };
        let (Some(left), Some(right)) = (left, right) else {
            evidence(
                &mut unavailable,
                inventory,
                &availability_left,
                &availability_right,
            );
            continue;
        };
        let names: BTreeSet<_> = left.keys().chain(right.keys()).collect();
        for name in names {
            let field = format!("{inventory}.{name}");
            match (left.get(name), right.get(name)) {
                (None, Some(value)) => change(
                    &mut changes,
                    &field,
                    "PACKAGE_ADDED",
                    Value::Null,
                    value.clone(),
                ),
                (Some(value), None) => change(
                    &mut changes,
                    &field,
                    "PACKAGE_REMOVED",
                    value.clone(),
                    Value::Null,
                ),
                (Some(left), Some(right)) => {
                    if !known(&left["version"]) || !known(&right["version"]) {
                        evidence(
                            &mut unavailable,
                            &format!("{field}.version"),
                            &left["version"],
                            &right["version"],
                        );
                    }
                    let mut comparable_left = left.clone();
                    let mut comparable_right = right.clone();
                    if !known(&left["version"]) || !known(&right["version"]) {
                        comparable_left.as_object_mut().unwrap().remove("version");
                        comparable_right.as_object_mut().unwrap().remove("version");
                    }
                    if !known(&left["artifact_hashes"]) || !known(&right["artifact_hashes"]) {
                        evidence(
                            &mut unavailable,
                            &format!("{field}.artifact_hashes"),
                            &left["artifact_hashes"],
                            &right["artifact_hashes"],
                        );
                        comparable_left
                            .as_object_mut()
                            .unwrap()
                            .remove("artifact_hashes");
                        comparable_right
                            .as_object_mut()
                            .unwrap()
                            .remove("artifact_hashes");
                    }
                    if known(&comparable_left)
                        && known(&comparable_right)
                        && comparable_left != comparable_right
                    {
                        change(
                            &mut changes,
                            &field,
                            "PACKAGE_CHANGED",
                            left.clone(),
                            right.clone(),
                        );
                    }
                }
                _ => unreachable!(),
            }
        }
    }
    changes.sort_by_key(|entry| entry["field"].as_str().unwrap().to_string());
    unavailable.sort_by_key(|entry| entry["field"].as_str().unwrap().to_string());
    Ok(
        json!({"diagnostics":if unavailable.is_empty(){vec![]}else{vec![json!({"level":"warning","code":"W_ENV_EVIDENCE_UNAVAILABLE","message":"Some environment evidence is unavailable; see unavailable fields."})]},"schema_version":1,"changes":changes,"complete":unavailable.is_empty(),"unavailable":unavailable,"causality":"not_inferred"}),
    )
}

pub(crate) fn call(args: Value) -> Result<String, String> {
    let before = args.get("before").ok_or("Missing before evidence")?;
    let after = args.get("after").ok_or("Missing after evidence")?;
    compare(before, after).map(|value| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn order_normalization_and_redacted_values_preserve_uncertainty() {
        let a = json!({"installed_packages":[{"name":"A_pkg","version":"1","artifact_hashes":["b","a"]}],"backend":{"name":"<redacted>"}});
        let b = json!({"installed_packages":[{"name":"a-pkg","version":"1","artifact_hashes":["a","b","a"]}],"backend":{"name":"<redacted>"}});
        let diff = compare(&a, &b).unwrap();
        assert!(diff["changes"].as_array().unwrap().is_empty());
        assert!(!diff["unavailable"].as_array().unwrap().is_empty());
        assert!(compare(&json!([]), &b).is_err());
        assert!(compare(&json!({"python":{"version":{"CUSTOM_ENV":"private"}}}), &b).is_err());
        assert!(compare(&json!({"installed_packages":[{"name":"x","version":"1"},{"name":"X","version":"2"}]}),&json!({"installed_packages":[]})).is_err());
    }
}
