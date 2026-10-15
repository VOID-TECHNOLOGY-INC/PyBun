//! Frozen backend graph inspection: no resolution, synchronization or receipts.
use super::*;

pub struct GraphEvidence {
    pub metadata: Value,
    pub backend: Value,
    pub lock: Value,
    pub packages: Vec<Value>,
}

pub fn provenance_graph(root: &Path) -> Result<GraphEvidence, BackendError> {
    let backend = UvBackend::discover(root)?;
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
