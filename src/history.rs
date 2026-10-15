//! Optional CLI execution receipts. Never store program output or environment variables.
use crate::cli::Commands;
use crate::proc_exec::{ProcExecOutcome, spawn_with_timeout};
use fs2::FileExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn enabled() -> bool {
    !matches!(
        std::env::var("PYBUN_HISTORY").as_deref(),
        Ok("0" | "false" | "off")
    )
}

fn path() -> Result<PathBuf, String> {
    crate::cache::Cache::new()
        .map(|cache| cache.root().join("history.jsonl"))
        .map_err(|_| "Cannot locate history storage".into())
}

fn timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

pub struct Pending {
    timestamp: u64,
    root: PathBuf,
    args: Vec<String>,
    lock_path: Option<PathBuf>,
}

impl Pending {
    pub fn begin(command: &Commands) -> Option<Self> {
        if !enabled()
            || !matches!(
                command,
                Commands::Run(_)
                    | Commands::Test(_)
                    | Commands::Install(_)
                    | Commands::Add(_)
                    | Commands::Remove(_)
            )
        {
            return None;
        }
        Some(Self {
            lock_path: match command {
                Commands::Install(args) => Some(args.lock.clone()),
                Commands::Run(args) => args
                    .target
                    .as_ref()
                    .map(|target| PathBuf::from(format!("{target}.lock"))),
                _ => None,
            },
            timestamp: timestamp_ms(),
            root: std::env::current_dir().ok()?,
            args: redact_args(std::env::args().skip(1)),
        })
    }

    pub fn finish(
        self,
        name: &str,
        detail: &Value,
        duration: Duration,
        exit_code: i32,
    ) -> Result<String, String> {
        let receipt_id = uuid::Uuid::new_v4().to_string();
        let root = self
            .root
            .ancestors()
            .find(|root| root.join("pyproject.toml").is_file())
            .unwrap_or(&self.root);
        let backend = detail.get("backend").filter(|v| v.is_object()).cloned().unwrap_or_else(|| json!({"name": if crate::backend::native_selected() { "native" } else { "unknown" }, "version": env!("CARGO_PKG_VERSION")}));
        let lock = detail.get("lock").cloned().unwrap_or_else(|| {
            let path = detail
                .get("lockfile")
                .and_then(Value::as_str)
                .map(PathBuf::from)
                .or(self.lock_path.clone())
                .filter(|path| path.is_file())
                .unwrap_or_else(|| root.join("pybun.lockb"));
            fs::read(&path)
                .ok()
                .map(|bytes| json!({"source":path,"digest":hex::encode(Sha256::digest(bytes))}))
                .unwrap_or(Value::Null)
        });
        // Use the backend's actual interpreter when supplied. Otherwise this is
        // explicitly an observation of the selected environment after the call,
        // not proof of an ephemeral interpreter used by a script/backend.
        let python_path = detail
            .pointer("/environment/python")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .or_else(|| {
                crate::env::find_python_env(&self.root)
                    .ok()
                    .map(|env| env.python_path)
            });
        let python = detail.get("execution_python").cloned().unwrap_or_else(|| {
            python_path
                .as_deref()
                .map(python_state)
                .unwrap_or(Value::Null)
        });
        let receipt = json!({
            "schema_version":1,"receipt_id":receipt_id,"timestamp_ms":self.timestamp,
            "command":name,"args":self.args,"project":{"path":root},
            "duration_ms":duration.as_millis().min(u64::MAX as u128) as u64,"exit_code":exit_code,
            "python":python,"python_observation":if detail.get("execution_python").is_some_and(|value| !value.is_null()) {"execution_interpreter_before_command"} else if detail.pointer("/environment/python").and_then(Value::as_str).is_some() {"backend_interpreter_after_command"} else {"selected_environment_after_command"},
            "backend":backend,"lock":lock,"packages":detail.get("packages"),
            "effective_policy":detail.get("effective_policy").or_else(||detail.get("sandbox")),
            "profile":detail.get("profile"),"cache_hit":detail.get("cache_hit"),
            "daemon_used":false,"backend_receipt_id":detail.get("receipt_id"),
        });
        append(&path()?, &crate::support_bundle::redact_protocol(&receipt))?;
        Ok(receipt_id)
    }
}

pub(crate) fn python_state(path: &Path) -> Value {
    if !enabled() {
        return Value::Null;
    }
    let mut command = Command::new(path);
    command.args(["-I", "-S", "-c", "import json,sys,sysconfig; print(json.dumps({'implementation':sys.implementation.name,'version':sys.version.split()[0],'abi':sysconfig.get_config_var('SOABI') or sys.implementation.cache_tag,'executable':sys.executable}))"]);
    match spawn_with_timeout(&mut command, Some(3), true) {
        Ok(ProcExecOutcome::Completed {
            status,
            stdout: Some(bytes),
            ..
        }) if status.success() => serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        _ => Value::Null,
    }
}

fn redact_args(args: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut hide_next = false;
    args.into_iter()
        .map(|arg| {
            if hide_next {
                hide_next = false;
                return "<redacted>".into();
            }
            if arg.starts_with("-c") && !arg.starts_with("--") && arg.len() > 2 {
                return "-c<redacted>".into();
            }
            let key = arg
                .split('=')
                .next()
                .unwrap_or_default()
                .trim_start_matches('-');
            if matches!(
                key,
                "c" | "code" | "token" | "password" | "secret" | "key" | "index" | "index-url"
            ) || crate::sandbox::is_credential_env_name(&key.replace('-', "_"))
            {
                if arg.contains('=') {
                    format!("{}=<redacted>", arg.split('=').next().unwrap_or_default())
                } else {
                    hide_next = true;
                    arg
                }
            } else {
                crate::support_bundle::redact_text(&arg)
            }
        })
        .collect()
}

fn open(path: &Path, create: bool) -> Result<File, String> {
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err("History storage must not be a symlink".into());
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(create)
        .append(create)
        .create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|_| "Cannot open history storage")?;
    if !file
        .metadata()
        .map_err(|_| "Cannot inspect history storage")?
        .is_file()
    {
        return Err("History storage must be a regular file".into());
    }
    #[cfg(unix)]
    if create {
        use std::os::unix::fs::PermissionsExt;
        if file
            .metadata()
            .map_err(|_| "Cannot inspect history permissions")?
            .permissions()
            .mode()
            & 0o077
            != 0
        {
            return Err("History storage permissions must restrict access to its owner (chmod 600 history.jsonl)".into());
        }
    }
    Ok(file)
}

fn append(path: &Path, receipt: &Value) -> Result<(), String> {
    fs::create_dir_all(path.parent().ok_or("Invalid history location")?)
        .map_err(|_| "Cannot create history directory")?;
    let mut file = open(path, true)?;
    file.lock_exclusive()
        .map_err(|_| "Cannot lock history storage")?;
    if file
        .metadata()
        .map_err(|_| "Cannot inspect history storage")?
        .len()
        > 0
    {
        file.seek(SeekFrom::End(-1))
            .map_err(|_| "Cannot inspect history tail")?;
        let mut tail = [0];
        file.read_exact(&mut tail)
            .map_err(|_| "Cannot read history tail")?;
        if tail[0] != b'\n' {
            file.write_all(b"\n")
                .map_err(|_| "Cannot preserve incomplete history tail")?;
        }
    }
    let mut bytes = serde_json::to_vec(receipt).map_err(|_| "Cannot encode history receipt")?;
    bytes.push(b'\n');
    file.write_all(&bytes)
        .map_err(|_| "Cannot append history receipt".into())
}

pub fn query(since: Option<&str>) -> Result<Value, String> {
    let cutoff = since.map(parse_duration).transpose()?.map(|duration| {
        timestamp_ms().saturating_sub(duration.as_millis().min(u64::MAX as u128) as u64)
    });
    let path = path()?;
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(json!({"records":[],"diagnostics":[]}));
        }
        Err(_) => return Err("Cannot inspect history storage".into()),
        Ok(_) => {}
    }
    let file = open(&path, false)?;
    FileExt::lock_shared(&file).map_err(|_| "Cannot lock history storage")?;
    if file
        .metadata()
        .map_err(|_| "Cannot inspect history storage")?
        .len()
        > 32 * 1024 * 1024
    {
        return Err(
            "History exceeds the 32 MiB query limit; archive history.jsonl before querying".into(),
        );
    }
    let mut records = Vec::new();
    let mut diagnostics = Vec::new();
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let value = line
            .ok()
            .and_then(|line| serde_json::from_str::<Value>(&line).ok());
        match value {
            Some(record) if record["schema_version"] == 1 && record["timestamp_ms"].is_u64() => {
                if cutoff.is_none_or(|cutoff| record["timestamp_ms"].as_u64().unwrap() >= cutoff) {
                    records.push(crate::support_bundle::redact_protocol(&record));
                }
            }
            _ => diagnostics.push(json!({"code":"E_HISTORY_RECORD_INVALID","line":index+1})),
        }
    }
    Ok(json!({"records":records,"diagnostics":diagnostics}))
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    let (digits, multiplier) = if let Some(value) = value.strip_suffix('s') {
        (value, 1)
    } else if let Some(value) = value.strip_suffix('m') {
        (value, 60)
    } else if let Some(value) = value.strip_suffix('h') {
        (value, 3600)
    } else if let Some(value) = value.strip_suffix('d') {
        (value, 86400)
    } else {
        return Err("Use --since with a positive duration such as 20m, 2h, or 1d".into());
    };
    digits
        .parse::<u64>()
        .ok()
        .filter(|number| *number > 0)
        .and_then(|number| number.checked_mul(multiplier))
        .map(Duration::from_secs)
        .ok_or_else(|| "Invalid history duration".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duration_and_redaction_are_strict() {
        assert_eq!(parse_duration("20m").unwrap(), Duration::from_secs(1200));
        for value in ["", "-1h", "0s", "2", "18446744073709551615d"] {
            assert!(parse_duration(value).is_err());
        }
        let args = redact_args(
            [
                "--token",
                "secret",
                "-c",
                "print('secret')",
                "https://user:pass@example.org/simple?token=hidden",
                "--safe",
            ]
            .map(String::from),
        );
        let joined = args.join(" ");
        assert!(
            !joined.contains("secret")
                && !joined.contains("hidden")
                && !joined.contains("user:pass"),
            "{joined}"
        );
        assert!(joined.contains("--safe"));
    }
    #[test]
    fn append_preserves_a_receipt_after_an_incomplete_tail() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("history.jsonl");
        let mut file = open(&path, true).unwrap();
        file.write_all(b"{incomplete").unwrap();
        drop(file);
        append(&path, &json!({"id": 1})).unwrap();
        let text = fs::read_to_string(path).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert_eq!(
            serde_json::from_str::<Value>(text.lines().nth(1).unwrap()).unwrap()["id"],
            1
        );
    }
    #[test]
    fn concurrent_append_retains_complete_records() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("history.jsonl");
        std::thread::scope(|scope| {
            for id in 0..20 {
                let path = &path;
                scope.spawn(move || append(path, &json!({"id":id})).unwrap());
            }
        });
        let records = fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 20);
    }
}
