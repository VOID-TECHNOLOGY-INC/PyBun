//! Frozen backend graph inspection: no resolution, synchronization or receipts.
use super::*;

pub struct GraphEvidence {
    pub metadata: Value,
    pub backend: Value,
    pub lock: Value,
    pub packages: Vec<Value>,
}

pub fn provenance_graph(root: &Path) -> Result<GraphEvidence, BackendError> {
    provenance_graph_scoped(root, Vec::new())
}
pub(crate) fn provenance_graph_scoped(
    root: &Path,
    roots: Vec<PathBuf>,
) -> Result<GraphEvidence, BackendError> {
    let backend = UvBackend::discover(root)?.scoped(roots);
    let root = backend.workspace_root()?;
    let lock = root.join("uv.lock");
    let (digest, packages) = read_lock(&lock)?;
    let mut command = backend.command("workspace");
    command.args([
        "metadata",
        "--frozen",
        "--offline",
        "--no-build",
        "--no-python-downloads",
    ]);
    let bytes = backend.spawn(&mut command, true)?;
    let unchanged = read_lock(&lock).is_ok_and(|(after, _)| after == digest);
    if !unchanged {
        return Err(error(
            "E_WHY_LOCK_CHANGED",
            "The lock changed during graph inspection; retry with a stable lockfile.",
        ));
    }
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(error(
            "E_WHY_GRAPH_INVALID",
            "Backend graph output exceeds the supported size.",
        ));
    }
    let metadata: Value = serde_json::from_slice(&bytes).map_err(|_| {
        error(
            "E_WHY_GRAPH_INVALID",
            "uv returned invalid graph JSON; use a supported uv version.",
        )
    })?;
    let expected = root.canonicalize().map_err(|_| {
        error(
            "E_WHY_GRAPH_INVALID",
            "Cannot verify the graph workspace identity.",
        )
    })?;
    if metadata["schema"]["version"] != "preview"
        || !metadata["workspace_root"].as_str().is_some_and(|path| {
            Path::new(path)
                .canonicalize()
                .is_ok_and(|path| path == expected)
        })
    {
        return Err(error(
            "E_WHY_GRAPH_INVALID",
            "uv returned an unsupported graph schema or workspace identity.",
        ));
    }
    Ok(GraphEvidence {
        metadata,
        backend: json!({"name":"uv","version":backend.version,"graph_source":"workspace_metadata"}),
        lock: json!({"source":lock,"digest":digest}),
        packages,
    })
}

/// Explicit read-only graph adapter for a private, preflighted snapshot. The
/// caller owns snapshot projection and authorization; legacy graph calls keep
/// their existing execution contract.
#[derive(Clone, Copy)]
pub struct BoundedGraphRequest<'a> {
    pub executable: &'a Path,
    pub root: &'a Path,
    pub directory: &'a cap_std::fs::Dir,
    pub max_output_bytes: usize,
    pub deadline: Instant,
}

pub fn provenance_graph_bounded(
    request: &BoundedGraphRequest<'_>,
) -> Result<GraphEvidence, BackendError> {
    let effective = BoundedGraphRequest {
        deadline: request
            .deadline
            .min(Instant::now() + std::time::Duration::from_secs(60)),
        ..*request
    };
    let request = &effective;
    if request.max_output_bytes == 0 || request.max_output_bytes > 5 * 1024 * 1024 {
        return Err(error(
            "E_SECURITY_GRAPH_LIMIT",
            "Graph output exceeds service bounds.",
        ));
    }
    let bytes = bounded_graph_file(request.directory, "uv.lock", request.max_output_bytes)?;
    let digest = crate::security::sha256_bytes(&bytes);
    let lock: toml::Value = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|text| toml::from_str(text).ok())
        .ok_or_else(|| {
            error(
                "E_SECURITY_GRAPH_INVALID",
                "The projected lock is malformed.",
            )
        })?;
    let packages = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| {
            error(
                "E_SECURITY_GRAPH_INVALID",
                "The projected lock has no package inventory.",
            )
        })?;
    let mut public_packages = Vec::new();
    for package in packages {
        let name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .filter(|name| name.len() <= 200)
            .ok_or_else(|| {
                error(
                    "E_SECURITY_GRAPH_INVALID",
                    "A projected lock package is malformed.",
                )
            })?;
        let version = package
            .get("version")
            .and_then(toml::Value::as_str)
            .filter(|version| version.len() <= 200)
            .ok_or_else(|| {
                error(
                    "E_SECURITY_GRAPH_INVALID",
                    "A projected lock package is malformed.",
                )
            })?;
        public_packages.push(json!({"name":name,"version":version}));
    }
    let version = bounded_graph_spawn(request, true)?;
    let version = std::str::from_utf8(&version)
        .ok()
        .and_then(|text| {
            let mut parts = text.split_whitespace();
            if parts.next() == Some("uv") {
                parts.next()
            } else {
                None
            }
        })
        .and_then(|value| semver::Version::parse(value).ok())
        .filter(|version| {
            *version >= semver::Version::new(0, 12, 0) && *version < semver::Version::new(0, 13, 0)
        })
        .ok_or_else(|| {
            error(
                "E_SECURITY_GRAPH_VERSION",
                "The graph adapter requires supported uv 0.12.x.",
            )
        })?;
    let output = bounded_graph_spawn(request, false)?;
    if bounded_graph_file(request.directory, "uv.lock", request.max_output_bytes)? != bytes {
        return Err(error(
            "E_SECURITY_GRAPH_INPUT_CHANGED",
            "The frozen graph lock changed during observation.",
        ));
    }
    let metadata: Value = serde_json::from_slice(&output).map_err(|_| {
        error(
            "E_SECURITY_GRAPH_INVALID",
            "The backend graph output is malformed.",
        )
    })?;
    if metadata.pointer("/schema/version").and_then(Value::as_str) != Some("preview")
        || !metadata
            .get("workspace_root")
            .and_then(Value::as_str)
            .is_some_and(|value| Path::new(value) == request.root)
        || !metadata
            .get("resolution")
            .and_then(Value::as_object)
            .is_some_and(|nodes| {
                nodes.len() <= 10000
                    && nodes.values().all(|node| {
                        node.get("name")
                            .is_none_or(|name| name.as_str().is_some_and(|name| name.len() <= 200))
                            && node.get("version").is_none_or(|version| {
                                version.as_str().is_some_and(|version| version.len() <= 200)
                            })
                            && node
                                .get("dependencies")
                                .and_then(Value::as_array)
                                .is_some_and(|edges| {
                                    edges.len() <= 10000
                                        && edges.iter().all(|edge| {
                                            edge.get("id")
                                                .and_then(Value::as_str)
                                                .is_some_and(|id| id.len() <= 8192)
                                                && edge.get("marker").is_none_or(|marker| {
                                                    marker.is_null()
                                                        || (marker.is_string()
                                                            && serde_json::to_vec(marker)
                                                                .is_ok_and(|encoded| {
                                                                    encoded.len() <= 1024
                                                                }))
                                                })
                                        })
                                })
                    })
            })
    {
        return Err(error(
            "E_SECURITY_GRAPH_INVALID",
            "The backend graph identity or schema is unsupported.",
        ));
    }
    if Instant::now() >= request.deadline {
        return Err(error(
            "E_SECURITY_GRAPH_LIMIT",
            "The graph observation deadline was exhausted.",
        ));
    }
    Ok(GraphEvidence {
        metadata,
        backend: json!({"name":"uv","version":version.to_string(),"graph_source":"bounded_frozen_workspace_metadata"}),
        lock: json!({"source":request.root.join("uv.lock"),"digest":digest}),
        packages: public_packages,
    })
}

fn bounded_graph_file(
    dir: &cap_std::fs::Dir,
    name: &str,
    limit: usize,
) -> Result<Vec<u8>, BackendError> {
    use std::io::Read;
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = dir.open_with(name, &options).map_err(|_| {
        error(
            "E_SECURITY_GRAPH_PATH",
            "The graph snapshot file cannot be read.",
        )
    })?;
    if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
        return Err(error(
            "E_SECURITY_GRAPH_PATH",
            "Graph inputs must be regular files.",
        ));
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| error("E_SECURITY_GRAPH_PATH", "The graph snapshot read failed."))?;
    if bytes.len() > limit {
        return Err(error(
            "E_SECURITY_GRAPH_LIMIT",
            "Graph input exceeds the observation budget.",
        ));
    }
    Ok(bytes)
}

fn bounded_graph_spawn(
    request: &BoundedGraphRequest<'_>,
    version: bool,
) -> Result<Vec<u8>, BackendError> {
    use std::io::Read;
    use std::process::Stdio;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    use std::time::Duration;
    if Instant::now() >= request.deadline {
        return Err(error(
            "E_SECURITY_GRAPH_LIMIT",
            "The graph observation deadline was exhausted.",
        ));
    }
    let mut command = Command::new(request.executable);
    command
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    anchor_graph_child(&mut command, request.directory)?;
    if version {
        command.arg("--version");
    } else {
        command
            .args(["--no-config", "--no-progress", "--cache-dir"])
            .arg("cache")
            .arg("--project")
            .arg(".")
            .args([
                "workspace",
                "metadata",
                "--frozen",
                "--offline",
                "--no-build",
                "--no-python-downloads",
                "--keyring-provider",
                "disabled",
            ]);
    }
    #[cfg(windows)]
    if let Some(value) = std::env::var_os("SYSTEMROOT") {
        command.env("SYSTEMROOT", value);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().map_err(|_| {
        error(
            "E_SECURITY_GRAPH_BACKEND",
            "The explicitly trusted graph backend could not start.",
        )
    })?;
    let overflow = Arc::new(AtomicBool::new(false));
    let reader = |mut pipe: Box<dyn Read + Send>, limit: usize, overflow: Arc<AtomicBool>| {
        let (send, receive) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = pipe.by_ref().take(limit as u64 + 1).read_to_end(&mut bytes);
            if bytes.len() > limit {
                overflow.store(true, Ordering::SeqCst);
            }
            let _ = send.send(result.map(|_| bytes));
        });
        receive
    };
    let out = reader(
        Box::new(child.stdout.take().unwrap()),
        if version {
            4096
        } else {
            request.max_output_bytes
        },
        overflow.clone(),
    );
    let err = reader(
        Box::new(child.stderr.take().unwrap()),
        16384,
        overflow.clone(),
    );
    let mut status = None;
    let mut stdout = None;
    let mut stderr = None;
    loop {
        if stdout.is_none() {
            stdout = out.try_recv().ok();
        }
        if stderr.is_none() {
            stderr = err.try_recv().ok();
        }
        if status.is_none() {
            status = child.try_wait().map_err(|_| {
                error(
                    "E_SECURITY_GRAPH_BACKEND",
                    "The graph backend status is unavailable.",
                )
            })?;
        }
        if overflow.load(Ordering::SeqCst) || Instant::now() >= request.deadline {
            crate::proc_exec::kill_process_tree(&mut child);
            let _ = child.wait();
            return Err(error(
                "E_SECURITY_GRAPH_LIMIT",
                "The graph backend exceeded its output or shared deadline budget.",
            ));
        }
        if status.is_some() && stdout.is_some() && stderr.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    if !status.is_some_and(|status| status.success())
        || stderr.is_some_and(|result| result.is_err())
    {
        return Err(error(
            "E_SECURITY_GRAPH_BACKEND",
            "The frozen graph backend failed; raw output is withheld.",
        ));
    }
    stdout.unwrap().map_err(|_| {
        error(
            "E_SECURITY_GRAPH_BACKEND",
            "The graph backend output could not be read.",
        )
    })
}

#[cfg(unix)]
fn anchor_graph_child(
    command: &mut Command,
    directory: &cap_std::fs::Dir,
) -> Result<(), BackendError> {
    use std::os::{fd::AsRawFd, unix::process::CommandExt};
    let directory = directory
        .try_clone()
        .map_err(|_| {
            error(
                "E_SECURITY_GRAPH_PATH",
                "The pinned graph directory cannot be cloned.",
            )
        })?
        .into_std_file();
    let change_directory = move || {
        // SAFETY: the owned directory File is captured by this closure and
        // stays open across fork until exec closes its CLOEXEC descriptor.
        // fchdir takes only that valid directory fd and is async-signal-safe.
        if unsafe { libc::fchdir(directory.as_raw_fd()) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    };
    // SAFETY: this callback runs only in the forked child. It performs fchdir
    // and an errno read, with no allocation, formatting, logging, locks or env
    // access. All cloning/capture setup happens above in the parent; the parent
    // working directory is never changed. Independent review covers this edge.
    unsafe {
        command.pre_exec(change_directory);
    }
    Ok(())
}
#[cfg(not(unix))]
fn anchor_graph_child(
    _command: &mut Command,
    _directory: &cap_std::fs::Dir,
) -> Result<(), BackendError> {
    Err(error(
        "E_SECURITY_GRAPH_PATH",
        "This platform cannot anchor the graph working directory.",
    ))
}
