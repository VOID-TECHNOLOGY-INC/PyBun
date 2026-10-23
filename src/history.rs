//! Optional CLI execution receipts. Never store program output or environment variables.
use crate::cli::Commands;
use fs2::FileExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
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
        let mut python = detail.get("execution_python").cloned().unwrap_or_else(|| {
            python_path
                .as_deref()
                .map(python_state)
                .unwrap_or(Value::Null)
        });
        let installed_packages = python
            .as_object_mut()
            .and_then(|value| value.remove("installed_packages"))
            .unwrap_or(Value::Null);
        let receipt = json!({
            "schema_version":1,"receipt_id":receipt_id,"timestamp_ms":self.timestamp,
            "command":name,"args":self.args,"project":{"path":root},
            "duration_ms":duration.as_millis().min(u64::MAX as u128) as u64,"exit_code":exit_code,
            "python":python,"python_observation":if detail.get("execution_python").is_some_and(|value| !value.is_null()) {"execution_interpreter_before_command"} else if detail.pointer("/environment/python").and_then(Value::as_str).is_some() {"backend_interpreter_after_command"} else {"selected_environment_after_command"},
            "backend":backend,"lock":lock,"packages":detail.get("packages"),"installed_packages":installed_packages,
            "effective_policy":detail.get("effective_policy").or_else(||detail.get("sandbox")),
            "profile":detail.get("profile"),"cache_hit":detail.get("cache_hit"),
            "daemon_used":false,"backend_receipt_id":detail.get("receipt_id"),
        });
        append(&path()?, &crate::support_bundle::redact_protocol(&receipt))?;
        Ok(receipt_id)
    }
}

/// Collect the interpreter identity and package inventory for a receipt.
///
/// This deliberately does not launch the interpreter: running
/// `python -I -S -c ...` cost 67-176 ms per command and dominated the startup
/// latency of every history-enabled invocation (Issue #516). The identity is
/// read from `pyvenv.cfg`, the executable name/symlink target and the
/// interpreter's `lib/pythonX.Y` layout; the inventory comes from
/// `*.dist-info/METADATA` in `site-packages`.
pub(crate) fn python_state(path: &Path) -> Value {
    if !enabled() {
        return Value::Null;
    }
    let venv = venv_root(path);
    let config = venv
        .as_deref()
        .and_then(|root| fs::read_to_string(root.join("pyvenv.cfg")).ok())
        .map(|text| parse_config(&text));
    let implementation = if path.to_string_lossy().contains("pypy") {
        "pypy"
    } else if path.to_string_lossy().contains("graalpy") {
        "graalpy"
    } else {
        "cpython"
    };
    let version = config
        .as_ref()
        .and_then(config_version)
        .or_else(|| version_from_path(path))
        .or_else(|| venv.as_deref().and_then(layout_version))
        .unwrap_or_else(|| "unknown".to_string());
    let abi = abi_tag(implementation, &version);
    let include_system = config
        .as_ref()
        .and_then(|config| config.get("include-system-site-packages"))
        .is_some_and(|value| value.eq_ignore_ascii_case("true"));
    // Only a self-contained venv has a complete inventory. A venv that sees
    // system site-packages, or a non-venv interpreter, cannot be represented
    // as an exhaustive package list.
    let packages = match (venv.as_deref(), include_system) {
        (Some(root), false) => Some(inventory(&site_packages(root, &version))),
        _ => None,
    };
    json!({
        "implementation": implementation,
        "version": version,
        "abi": abi,
        "executable": absolute(path),
        "executable_digest": fs::read(path).ok().map(|bytes| hex::encode(Sha256::digest(bytes))),
        "installed_packages": packages,
    })
}

fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    std::env::current_dir()
        .map(|cwd| cwd.join(path))
        .unwrap_or_else(|_| path.to_path_buf())
}

fn venv_root(path: &Path) -> Option<PathBuf> {
    let root = path.parent()?.parent()?;
    root.join("pyvenv.cfg")
        .is_file()
        .then(|| root.to_path_buf())
}

fn parse_config(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            Some((key.trim().to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect()
}

fn config_version(config: &BTreeMap<String, String>) -> Option<String> {
    ["version", "version_info", "python-version"]
        .iter()
        .find_map(|key| config.get(*key).and_then(|value| normalize_version(value)))
}

/// Normalize `3.12.14`, `3.13.14.final.0`, or `3.12` to `major.minor[.micro]`.
fn normalize_version(raw: &str) -> Option<String> {
    let mut parts = Vec::new();
    for part in raw.trim().split('.') {
        if parts.len() == 3 || part.is_empty() || !part.chars().all(|ch| ch.is_ascii_digit()) {
            break;
        }
        parts.push(part);
    }
    (parts.len() >= 2).then(|| parts.join("."))
}

fn version_from_name(name: &str) -> Option<String> {
    normalize_version(name.strip_prefix("python")?)
}

fn version_from_path(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    if let Some(version) = version_from_name(name) {
        return Some(version);
    }
    // venv `bin/python` is usually a symlink to a versioned interpreter.
    let mut current = path.to_path_buf();
    for _ in 0..8 {
        let target = fs::read_link(&current).ok()?;
        current = if target.is_absolute() {
            target
        } else {
            current.parent()?.join(target)
        };
        if let Some(version) = current
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(version_from_name)
        {
            return Some(version);
        }
    }
    None
}

/// Look for `lib/pythonX.Y` next to the interpreter when the name carries no
/// version (for example a distro's `/usr/bin/python3`).
fn layout_version(root: &Path) -> Option<String> {
    for lib in [root.join("lib"), root.join("lib64"), root.join("Lib")] {
        let Ok(entries) = fs::read_dir(lib) else {
            continue;
        };
        let mut versions = entries
            .flatten()
            .filter_map(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .and_then(version_from_name)
                    .filter(|_| entry.path().is_dir())
            })
            .collect::<Vec<_>>();
        versions.sort();
        if let Some(version) = versions.pop() {
            return Some(version);
        }
    }
    None
}

fn abi_tag(implementation: &str, version: &str) -> String {
    let digits = version
        .split('.')
        .take(2)
        .filter(|part| part.chars().all(|ch| ch.is_ascii_digit()))
        .collect::<String>();
    if digits.len() >= 2 {
        format!("{implementation}-{digits}")
    } else {
        "unknown".to_string()
    }
}

fn site_packages(root: &Path, version: &str) -> Vec<PathBuf> {
    let mut dirs = BTreeSet::new();
    for lib in [root.join("lib"), root.join("lib64")] {
        if let Ok(entries) = fs::read_dir(&lib) {
            for entry in entries.flatten() {
                if entry.file_name().to_string_lossy().starts_with("python") {
                    let site = entry.path().join("site-packages");
                    if site.is_dir() {
                        dirs.insert(site);
                    }
                }
            }
        }
    }
    let windows = root.join("Lib").join("site-packages");
    if windows.is_dir() {
        dirs.insert(windows);
    }
    if dirs.is_empty() && version != "unknown" {
        let parts = version.split('.').take(2).collect::<Vec<_>>();
        if parts.len() == 2 {
            for lib in [root.join("lib"), root.join("lib64")] {
                let site = lib
                    .join(format!("python{}.{}", parts[0], parts[1]))
                    .join("site-packages");
                if site.is_dir() {
                    dirs.insert(site);
                }
            }
        }
    }
    dirs.into_iter().collect()
}

fn inventory(dirs: &[PathBuf]) -> Vec<Value> {
    let mut packages = BTreeSet::new();
    for dir in dirs {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(stem) = name
                .to_string_lossy()
                .strip_suffix(".dist-info")
                .map(str::to_string)
            else {
                continue;
            };
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let Some((fallback_name, fallback_version)) = stem.rsplit_once('-') else {
                continue;
            };
            let (name, version) = dist_metadata(&path)
                .unwrap_or_else(|| (fallback_name.to_string(), fallback_version.to_string()));
            if name.is_empty()
                || !name
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || "-_.".contains(ch))
                || crate::pep440::Pep440Version::parse(&version).is_none()
            {
                continue;
            }
            packages.insert((name, version));
            if packages.len() > 5000 {
                return Vec::new();
            }
        }
    }
    packages
        .into_iter()
        .map(|(name, version)| json!({"name":name,"version":version,"artifact_hashes":null}))
        .collect()
}

fn dist_metadata(path: &Path) -> Option<(String, String)> {
    let text = fs::read_to_string(path.join("METADATA")).ok()?;
    let mut name = None;
    let mut version = None;
    for line in text.lines() {
        if line.is_empty() {
            break;
        }
        if let Some(value) = line.strip_prefix("Name:") {
            name = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("Version:") {
            version = Some(value.trim().to_string());
        }
    }
    Some((name?, version?))
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

    fn write_dist_info(site: &Path, name: &str, version: &str) {
        let dir = site.join(format!("{name}-{version}.dist-info"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("METADATA"),
            format!("Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\nsummary\n"),
        )
        .unwrap();
    }

    #[test]
    fn normalizes_version_lines_from_every_venv_creator() {
        assert_eq!(normalize_version("3.12.14").as_deref(), Some("3.12.14"));
        assert_eq!(
            normalize_version("3.13.14.final.0").as_deref(),
            Some("3.13.14")
        );
        assert_eq!(normalize_version("3.12").as_deref(), Some("3.12"));
        assert_eq!(normalize_version("unknown"), None);

        let stdlib = parse_config("home = /usr/bin\nversion = 3.12.14\n");
        assert_eq!(config_version(&stdlib).as_deref(), Some("3.12.14"));
        let uv = parse_config("version_info = 3.12.14\ninclude-system-site-packages = false\n");
        assert_eq!(config_version(&uv).as_deref(), Some("3.12.14"));
        let virtualenv = parse_config(
            "python-version = 3.13\nversion_info = 3.13.14.final.0\nversion = 3.13.14\n",
        );
        assert_eq!(config_version(&virtualenv).as_deref(), Some("3.13.14"));
    }

    #[test]
    fn python_state_reads_a_venv_without_launching_an_interpreter() {
        let temp = tempfile::tempdir().unwrap();
        let venv = temp.path().join("venv");
        let bin = venv.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let python = bin.join(format!("python{}", std::env::consts::EXE_SUFFIX));
        fs::write(&python, b"not-a-real-interpreter").unwrap();
        fs::write(
            venv.join("pyvenv.cfg"),
            "version_info = 3.12.14\ninclude-system-site-packages = false\n",
        )
        .unwrap();
        let site = venv.join("lib").join("python3.12").join("site-packages");
        fs::create_dir_all(&site).unwrap();
        write_dist_info(&site, "Demo-Pkg", "1.2.3");
        write_dist_info(&site, "Other", "0.1.0");

        let state = python_state(&python);
        assert_eq!(state["implementation"], "cpython");
        assert_eq!(state["version"], "3.12.14");
        assert_eq!(state["abi"], "cpython-312");
        assert_eq!(
            state["executable"].as_str().unwrap(),
            python.to_str().unwrap()
        );
        assert_eq!(
            state["installed_packages"],
            json!([
                {"name":"Demo-Pkg","version":"1.2.3","artifact_hashes":null},
                {"name":"Other","version":"0.1.0","artifact_hashes":null},
            ])
        );
    }

    #[test]
    fn system_site_packages_disable_the_complete_inventory() {
        let temp = tempfile::tempdir().unwrap();
        let venv = temp.path().join("venv");
        let bin = venv.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let python = bin.join(format!("python{}", std::env::consts::EXE_SUFFIX));
        fs::write(&python, b"not-a-real-interpreter").unwrap();
        fs::write(
            venv.join("pyvenv.cfg"),
            "version = 3.11.9\ninclude-system-site-packages = true\n",
        )
        .unwrap();
        let site = venv.join("lib").join("python3.11").join("site-packages");
        fs::create_dir_all(&site).unwrap();
        write_dist_info(&site, "Demo", "1.0.0");

        let state = python_state(&python);
        assert_eq!(state["version"], "3.11.9");
        assert!(state["installed_packages"].is_null());
    }

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
