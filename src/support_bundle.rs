use crate::cache::Cache;
use crate::paths::{ArtifactInfo, PyBunPaths};
use crate::telemetry::DEFAULT_REDACTION_PATTERNS;
use base64::Engine;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_FILE_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub struct BundleContext {
    pub checks: Vec<Value>,
    pub verbose_logs: bool,
    pub trace_id: Option<String>,
    pub command: String,
}

#[derive(Debug, Clone)]
pub struct BundleFile {
    pub path: String,
    pub bytes: u64,
    pub truncated: bool,
    pub redactions: usize,
    pub encoding: Option<String>,
}

#[derive(Debug)]
pub struct BundleCollection {
    pub path: PathBuf,
    pub files: Vec<BundleFile>,
    pub redactions: usize,
    pub logs_included: bool,
}

#[derive(Debug)]
pub struct UploadOutcome {
    pub url: String,
    pub status: String,
    pub http_status: Option<u16>,
    pub error: Option<String>,
}

#[derive(Debug)]
pub struct BundleReport {
    pub bundle_path: Option<PathBuf>,
    pub files: Vec<BundleFile>,
    pub redactions: usize,
    pub logs_included: bool,
    pub upload: Option<UploadOutcome>,
}

static CRASH_HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);

pub fn install_crash_hook() {
    if CRASH_HOOK_INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }

    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        previous(info);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if !should_offer_crash_bundle() {
                return;
            }
            if !io::stderr().is_terminal() || !io::stdin().is_terminal() {
                return;
            }
            if !prompt_yes_no("PyBun crashed. Create a support bundle? [y/N] ") {
                return;
            }

            let support_dir = default_support_dir();
            let bundle_dir = support_dir.join(format!("crash-{}", unix_timestamp()));
            let context = BundleContext {
                checks: vec![json!({
                    "name": "crash",
                    "status": "error",
                    "message": info.to_string(),
                })],
                verbose_logs: true,
                trace_id: None,
                command: "pybun crash".to_string(),
            };

            match build_support_bundle(&bundle_dir, &context) {
                Ok(collection) => {
                    eprintln!("Support bundle written to {}", collection.path.display());
                    if let Ok(url) = std::env::var("PYBUN_SUPPORT_UPLOAD_URL") {
                        let outcome = upload_bundle(&collection, &url);
                        if outcome.status == "uploaded" {
                            eprintln!("Support bundle uploaded to {}", url);
                        } else if let Some(err) = outcome.error {
                            eprintln!("Support bundle upload failed: {}", err);
                        }
                    }
                }
                Err(err) => {
                    eprintln!("Support bundle creation failed: {:?}", err);
                }
            }
        }));
    }));
}

impl BundleReport {
    pub fn to_json(&self) -> Value {
        let files: Vec<Value> = self
            .files
            .iter()
            .map(|file| {
                json!({
                    "path": file.path,
                    "bytes": file.bytes,
                    "truncated": file.truncated,
                    "redactions": file.redactions,
                    "encoding": file.encoding,
                })
            })
            .collect();

        json!({
            "path": self.bundle_path.as_ref().map(|path| path.display().to_string()),
            "files": files,
            "redactions": self.redactions,
            "logs_included": self.logs_included,
            "upload": self.upload.as_ref().map(|upload| {
                json!({
                    "url": upload.url,
                    "status": upload.status,
                    "http_status": upload.http_status,
                    "error": upload.error,
                })
            }),
        })
    }
}

#[derive(Debug)]
pub enum BundleError {
    Io(String),
    Serialize(String),
}

impl From<std::io::Error> for BundleError {
    fn from(err: std::io::Error) -> Self {
        BundleError::Io(err.to_string())
    }
}

impl From<serde_json::Error> for BundleError {
    fn from(err: serde_json::Error) -> Self {
        BundleError::Serialize(err.to_string())
    }
}

pub fn build_support_bundle(
    path: &Path,
    context: &BundleContext,
) -> Result<BundleCollection, BundleError> {
    if path.exists() && !path.is_dir() {
        return Err(BundleError::Io(format!(
            "bundle path is not a directory: {}",
            path.display()
        )));
    }

    fs::create_dir_all(path)?;

    let rules = RedactionRules::default();
    let mut files = Vec::new();
    let mut total_redactions = 0usize;

    let manifest = build_manifest(context);
    let manifest_path = path.join("manifest.json");
    let (file, redactions) = write_json_file(&manifest_path, &manifest, &rules)?;
    files.push(file);
    total_redactions += redactions;

    let doctor_path = path.join("doctor.json");
    let doctor_json = json!({
        "checks": context.checks,
        "trace_id": context.trace_id,
    });
    let (file, redactions) = write_json_file(&doctor_path, &doctor_json, &rules)?;
    files.push(file);
    total_redactions += redactions;

    let env_path = path.join("env.json");
    let env_json = collect_env_json(&rules);
    let (file, redactions) = write_json_file(&env_path, &env_json, &rules)?;
    files.push(file);
    total_redactions += redactions;

    let versions_path = path.join("versions.json");
    let versions_json = build_versions_json(context.trace_id.as_deref());
    let (file, redactions) = write_json_file(&versions_path, &versions_json, &rules)?;
    files.push(file);
    total_redactions += redactions;

    let mut logs_included = false;
    if context.verbose_logs {
        let mut log_files = Vec::new();
        if let Ok(paths) = PyBunPaths::new() {
            log_files.extend(collect_files(&paths.logs_dir()));
        }
        if let Ok(cache) = Cache::new() {
            log_files.extend(collect_files(&cache.logs_dir()));
        }
        for log_file in log_files {
            let rel = bundle_relpath("logs", &log_file);
            let dest = path.join(&rel);
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }
            let (file, redactions) = write_sanitized_file(&log_file, &dest, &rules)?;
            files.push(BundleFile { path: rel, ..file });
            total_redactions += redactions;
        }
        logs_included = true;
    }

    let mut config_files = Vec::new();
    if let Ok(paths) = PyBunPaths::new() {
        let telemetry = paths.root().join("telemetry.json");
        if telemetry.exists() {
            config_files.push(telemetry);
        }
    }
    let env_cache = crate::env::pybun_home().join("env_cache.json");
    if env_cache.exists() {
        config_files.push(env_cache);
    }

    for config_file in config_files {
        let rel = bundle_relpath("config", &config_file);
        let dest = path.join(&rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        let (file, redactions) = write_sanitized_file(&config_file, &dest, &rules)?;
        files.push(BundleFile { path: rel, ..file });
        total_redactions += redactions;
    }

    Ok(BundleCollection {
        path: path.to_path_buf(),
        files,
        redactions: total_redactions,
        logs_included,
    })
}

pub fn upload_bundle(bundle: &BundleCollection, upload_url: &str) -> UploadOutcome {
    let payload = json!({
        "bundle_path": bundle.path.display().to_string(),
        "files": bundle
            .files
            .iter()
            .map(|file| {
                let content = fs::read(bundle.path.join(&file.path))
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok());
                json!({
                    "path": file.path,
                    "bytes": file.bytes,
                    "truncated": file.truncated,
                    "redactions": file.redactions,
                    "encoding": file.encoding,
                    "content": content,
                })
            })
            .collect::<Vec<_>>(),
    });
    let upload_url = upload_url.to_string();
    let payload = payload.clone();
    let upload_url_thread = upload_url.clone();

    std::thread::spawn(move || {
        let client = reqwest::blocking::Client::new();
        match client.post(&upload_url_thread).json(&payload).send() {
            Ok(response) => UploadOutcome {
                url: upload_url_thread.clone(),
                status: if response.status().is_success() {
                    "uploaded".to_string()
                } else {
                    "failed".to_string()
                },
                http_status: Some(response.status().as_u16()),
                error: response.error_for_status().err().map(|err| err.to_string()),
            },
            Err(err) => UploadOutcome {
                url: upload_url_thread.clone(),
                status: "failed".to_string(),
                http_status: None,
                error: Some(err.to_string()),
            },
        }
    })
    .join()
    .unwrap_or_else(|_| UploadOutcome {
        url: upload_url,
        status: "failed".to_string(),
        http_status: None,
        error: Some("upload thread panicked".to_string()),
    })
}

fn build_manifest(context: &BundleContext) -> Value {
    json!({
        "schema": 1,
        "command": context.command,
        "created_at": unix_timestamp(),
        "trace_id": context.trace_id,
    })
}

fn build_versions_json(trace_id: Option<&str>) -> Value {
    let artifact = ArtifactInfo::from_env();
    json!({
        "pybun_version": artifact.version,
        "target": artifact.target,
        "commit": artifact.commit,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "trace_id": trace_id,
    })
}

fn collect_env_json(rules: &RedactionRules) -> Value {
    let mut env_map: BTreeMap<String, String> = BTreeMap::new();
    for (key, value) in std::env::vars() {
        let (redacted, _) = rules.redact_value(&key, &value);
        env_map.insert(key, redacted);
    }
    json!({ "environment": env_map })
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn default_support_dir() -> PathBuf {
    if let Ok(paths) = PyBunPaths::new() {
        paths.root().join("support")
    } else {
        std::env::temp_dir().join("pybun-support")
    }
}

fn should_offer_crash_bundle() -> bool {
    if let Ok(value) = std::env::var("PYBUN_CRASH_REPORT") {
        let value = value.trim().to_ascii_lowercase();
        return matches!(value.as_str(), "1" | "true" | "yes" | "on" | "ask");
    }
    true
}

fn prompt_yes_no(prompt: &str) -> bool {
    eprint!("{}", prompt);
    let _ = io::stderr().flush();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn bundle_relpath(prefix: &str, path: &Path) -> String {
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    format!("{}/{}", prefix, file_name)
}

fn collect_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if !root.exists() {
        return files;
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files
}

fn write_json_file(
    path: &Path,
    value: &Value,
    rules: &RedactionRules,
) -> Result<(BundleFile, usize), BundleError> {
    // `redact_json_value` is structural: it replaces values while preserving
    // JSON syntax. Running the line-based text redactor afterwards rewrote
    // keys/indentation/quotes and produced invalid JSON whenever a
    // credential-like name was present (Issue #518).
    let redacted = rules.redact_json_value(value);
    let content = serde_json::to_string_pretty(&redacted)?;
    let redactions = content.matches("<redacted>").count();
    write_prepared_file(path, &content, redactions)
}

fn write_prepared_file(
    path: &Path,
    content: &str,
    redactions: usize,
) -> Result<(BundleFile, usize), BundleError> {
    fs::write(path, content.as_bytes())?;
    let bytes = fs::metadata(path)?.len();
    Ok((
        BundleFile {
            path: path
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            bytes,
            truncated: false,
            redactions,
            encoding: None,
        },
        redactions,
    ))
}

fn write_sanitized_file(
    src: &Path,
    dest: &Path,
    rules: &RedactionRules,
) -> Result<(BundleFile, usize), BundleError> {
    let mut file = fs::File::open(src)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let truncated = buffer.len() > MAX_FILE_BYTES;
    if truncated {
        buffer.truncate(MAX_FILE_BYTES);
    }

    if let Ok(text) = std::str::from_utf8(&buffer) {
        if let Ok(json_value) = serde_json::from_str::<Value>(text) {
            let redacted = rules.redact_json_value(&json_value);
            let content = serde_json::to_string_pretty(&redacted)?;
            fs::write(dest, content.as_bytes())?;
            let bytes = fs::metadata(dest)?.len();
            let redactions = rules.redact_text(&content).1;
            return Ok((
                BundleFile {
                    path: dest
                        .file_name()
                        .map(|name| name.to_string_lossy().to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    bytes,
                    truncated,
                    redactions,
                    encoding: None,
                },
                redactions,
            ));
        }

        let (sanitized, redactions) = rules.redact_text(text);
        fs::write(dest, sanitized.as_bytes())?;
        let bytes = fs::metadata(dest)?.len();
        return Ok((
            BundleFile {
                path: dest
                    .file_name()
                    .map(|name| name.to_string_lossy().to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                bytes,
                truncated,
                redactions,
                encoding: None,
            },
            redactions,
        ));
    }

    let engine = base64::engine::general_purpose::STANDARD;
    let encoded = engine.encode(buffer);
    fs::write(dest, encoded.as_bytes())?;
    let bytes = fs::metadata(dest)?.len();
    Ok((
        BundleFile {
            path: dest
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            bytes,
            truncated,
            redactions: 0,
            encoding: Some("base64".to_string()),
        },
        0,
    ))
}

#[derive(Debug)]
struct RedactionRules {
    patterns: Vec<String>,
    secret_values: Vec<String>,
}

pub fn redact_text(text: &str) -> String {
    RedactionRules::default().redact_text(text).0
}

pub(crate) fn redact_json(value: &Value) -> Value {
    RedactionRules::default().redact_json_value(value)
}

pub(crate) fn redact_protocol(value: &Value) -> Value {
    RedactionRules::default().redact_json_field("", value, true)
}

pub fn redact_response(text: &str) -> String {
    match serde_json::from_str::<Value>(text) {
        Ok(value) => redact_protocol(&value).to_string(),
        Err(_) => redact_text(text),
    }
}

impl Default for RedactionRules {
    fn default() -> Self {
        let mut patterns: Vec<String> = DEFAULT_REDACTION_PATTERNS
            .iter()
            .map(|pattern| pattern.to_string())
            .collect();
        patterns.extend([
            "*TOKEN*".to_string(),
            "*PASSWORD*".to_string(),
            "*SECRET*".to_string(),
            "*KEY*".to_string(),
            "*USERNAME*".to_string(),
        ]);
        let mut secret_values = Vec::new();
        for (name, value) in std::env::vars() {
            if crate::sandbox::is_credential_env_name(&name) && !value.is_empty() {
                if !crate::sandbox::is_index_env_name(&name)
                    || name.to_ascii_uppercase().ends_with("_USERNAME")
                    || name.to_ascii_uppercase().ends_with("_PASSWORD")
                {
                    secret_values.push(value.clone());
                }
                if crate::sandbox::is_index_env_name(&name) {
                    for item in value.split_whitespace() {
                        let parsed = reqwest::Url::parse(item).ok().or_else(|| {
                            item.split_once('=')
                                .and_then(|(_, url)| reqwest::Url::parse(url).ok())
                        });
                        if let Some(url) = parsed {
                            for credential in [Some(url.username()), url.password()]
                                .into_iter()
                                .flatten()
                                .filter(|v| !v.is_empty())
                            {
                                let mut decoder = url.clone();
                                decoder.set_query(Some(&format!(
                                    "v={}",
                                    credential.replace('+', "%2B")
                                )));
                                let decoded = decoder.query_pairs().next().unwrap().1.into_owned();
                                secret_values.push(decoded);
                            }
                        }
                    }
                }
            }
        }
        secret_values.sort_by_key(|value| std::cmp::Reverse(value.len()));
        secret_values.dedup();
        Self {
            patterns,
            secret_values,
        }
    }
}

impl RedactionRules {
    fn redact_value(&self, key: &str, value: &str) -> (String, usize) {
        if self.key_matches(key) {
            return ("<redacted>".to_string(), 1);
        }
        self.redact_text(value)
    }

    fn redact_text(&self, text: &str) -> (String, usize) {
        let mut redactions = 0usize;
        let mut output = String::new();
        for line in text.split_inclusive('\n') {
            let ending = if line.ends_with("\r\n") {
                "\r\n"
            } else if line.ends_with('\n') {
                "\n"
            } else {
                ""
            };
            let mut current = line.to_string();
            if let Some((key, delimiter)) = extract_key_delimiter(line)
                && self.key_matches(&key)
                && key
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c))
            {
                current = format!("{}{} <redacted>{ending}", key, delimiter);
                redactions += 1;
            }
            let (url_redacted, count) = redact_url_credentials(&current);
            current = url_redacted;
            redactions += count;

            for secret in &self.secret_values {
                if current.contains(secret) {
                    current = current.replace(secret, "<redacted>");
                    redactions += 1;
                }
            }

            let (query_redacted, count) = redact_query_params(&current);
            current = query_redacted;
            redactions += count;

            output.push_str(&current);
        }
        (output, redactions)
    }

    fn redact_json_value(&self, value: &Value) -> Value {
        self.redact_json_field("", value, false)
    }

    fn redact_json_field(&self, field: &str, value: &Value, protocol: bool) -> Value {
        match value {
            Value::Object(map) => {
                let mut redacted = serde_json::Map::new();
                for (key, value) in map {
                    if self.key_matches(key) {
                        redacted.insert(key.clone(), Value::String("<redacted>".to_string()));
                    } else {
                        redacted.insert(key.clone(), self.redact_json_field(key, value, protocol));
                    }
                }
                Value::Object(redacted)
            }
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|item| self.redact_json_field(field, item, protocol))
                    .collect(),
            ),
            Value::String(text) => {
                // Typed protocol fields describe execution identity, not authentication.
                if protocol
                    && matches!(
                        field,
                        "name"
                            | "version"
                            | "status"
                            | "operation"
                            | "contract_version"
                            | "code"
                            | "level"
                            | "type"
                            | "source"
                            | "path"
                            | "python"
                            | "lock_source"
                            | "fingerprint"
                            | "digest"
                            | "receipt_id"
                            | "input_hash"
                            | "session_id"
                            | "timestamp"
                            | "command"
                            | "target"
                            | "script"
                    )
                {
                    let (text, _) = redact_url_credentials(text);
                    return Value::String(redact_query_params(&text).0);
                }
                let (redacted, _) = self.redact_text(text);
                Value::String(redacted)
            }
            other => other.clone(),
        }
    }

    fn key_matches(&self, key: &str) -> bool {
        if crate::sandbox::is_index_env_name(key) {
            return true;
        }
        let uppercase = key.to_ascii_uppercase();
        self.patterns
            .iter()
            .any(|pattern| glob_match(pattern, &uppercase))
    }
}

fn extract_key_delimiter(line: &str) -> Option<(String, String)> {
    if let Some(pos) = line.find('=') {
        let key = line[..pos].trim().trim_matches('"').to_string();
        return Some((key, "=".to_string()));
    }
    if let Some(pos) = line.find(':') {
        let key = line[..pos].trim().trim_matches('"').to_string();
        return Some((key, ":".to_string()));
    }
    None
}

fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let mut parts = pattern.split('*').collect::<Vec<_>>();
    if parts.len() == 1 {
        return pattern == text;
    }

    let mut remainder = text;
    let starts_with_wildcard = pattern.starts_with('*');
    let ends_with_wildcard = pattern.ends_with('*');

    if !starts_with_wildcard {
        let start = parts.remove(0);
        if !remainder.starts_with(start) {
            return false;
        }
        remainder = &remainder[start.len()..];
    }

    if !ends_with_wildcard {
        let end = parts.pop().unwrap_or_default();
        if !remainder.ends_with(end) {
            return false;
        }
        remainder = &remainder[..remainder.len() - end.len()];
    }

    for part in parts {
        if part.is_empty() {
            continue;
        }
        if let Some(idx) = remainder.find(part) {
            remainder = &remainder[idx + part.len()..];
        } else {
            return false;
        }
    }

    true
}

fn redact_url_credentials(input: &str) -> (String, usize) {
    let mut redactions = 0usize;
    let mut output = input.to_string();
    let mut offset = 0usize;
    while let Some(pos) = output[offset..].find("://") {
        let scheme_end = offset + pos + 3;
        let remainder = &output[scheme_end..];
        let authority_end = remainder
            .find(['/', '?', '#', ' ', '\t', '\r', '\n', '"', '\''])
            .unwrap_or(remainder.len());
        if let Some(at_pos) = remainder[..authority_end].rfind('@') {
            let before_at = &remainder[..at_pos];
            if before_at.contains(':') || !before_at.is_empty() {
                let replace_start = scheme_end;
                let replace_end = scheme_end + at_pos;
                output.replace_range(replace_start..replace_end, "<redacted>");
                redactions += 1;
                offset = replace_start + "<redacted>".len() + 1;
                continue;
            }
        }
        offset = scheme_end;
    }
    (output, redactions)
}

fn redact_query_params(input: &str) -> (String, usize) {
    let keys = ["token", "password", "secret", "key", "access_token"];
    let mut redactions = 0usize;
    let mut output = input.to_string();
    for key in keys {
        let mut search = output.to_ascii_lowercase();
        let mut start = 0usize;
        while let Some(pos) = search[start..].find(&format!("{}=", key)) {
            let abs = start + pos;
            let value_start = abs + key.len() + 1;
            let value_end = output[value_start..]
                .find(&['&', ' ', '"', '\'', '\r', '\n'][..])
                .map(|idx| value_start + idx)
                .unwrap_or(output.len());
            output.replace_range(value_start..value_end, "<redacted>");
            redactions += 1;
            search = output.to_ascii_lowercase();
            start = value_start + "<redacted>".len();
        }
    }
    (output, redactions)
}

#[cfg(test)]
mod tests {
    #[test]
    fn auth_values_do_not_corrupt_protocol_fields() {
        let rules = super::RedactionRules {
            secret_values: vec!["uv".into(), "success".into()],
            ..Default::default()
        };
        let value = serde_json::json!({"status":"success", "backend":{"name":"uv"}, "lock":{"source":"/tmp/uv.lock"}, "stdout":"uv\n"});
        let redacted = rules.redact_json_field("", &value, true);
        assert_eq!(redacted["backend"]["name"], "uv");
        assert_eq!(redacted["status"], "success");
        assert_eq!(redacted["lock"]["source"], "/tmp/uv.lock");
        assert_eq!(redacted["stdout"], "<redacted>\n");
    }

    #[test]
    fn authenticated_urls_redact_passwords_with_at_signs() {
        let (text, _) =
            super::redact_url_credentials("https://user:prefix@secret-tail@example.org/simple");
        assert_eq!(text, "https://<redacted>@example.org/simple");
    }
    #[test]
    fn auth_redaction_preserves_output_whitespace() {
        let rules = super::RedactionRules::default();
        assert_eq!(rules.redact_text("hello\r\n\n").0, "hello\r\n\n");
        let value = serde_json::json!({"UV_INDEX_PRIVATE_USERNAME": "secret-user"});
        assert!(
            !rules
                .redact_json_value(&value)
                .to_string()
                .contains("secret-user")
        );
    }
    use super::*;

    #[test]
    fn redacts_env_key_patterns() {
        let rules = RedactionRules::default();
        let (value, redactions) = rules.redact_value("PYBUN_API_TOKEN", "secret");
        assert_eq!(value, "<redacted>");
        assert_eq!(redactions, 1);
    }

    #[test]
    fn redacts_url_credentials() {
        let (redacted, count) = redact_url_credentials("https://user:pass@example.com");
        assert_eq!(redacted, "https://<redacted>@example.com");
        assert_eq!(count, 1);
    }

    #[test]
    fn redacts_json_keys() {
        let rules = RedactionRules::default();
        let value = json!({
            "token": "abc",
            "nested": { "password": "secret" },
            "safe": "ok",
        });
        let redacted = rules.redact_json_value(&value);
        assert_eq!(redacted["token"], "<redacted>");
        assert_eq!(redacted["nested"]["password"], "<redacted>");
        assert_eq!(redacted["safe"], "ok");
    }
}
