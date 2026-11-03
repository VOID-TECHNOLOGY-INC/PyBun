//! Installed-parent evidence joined to the existing frozen lock graph adapter.
//! Only a static, secret-free single-project projection is given to uv. Locked
//! paths retain activation:not_evaluated; installed metadata owns constraints.
use crate::backend::{BoundedGraphRequest, GraphEvidence, provenance_graph_bounded};
use crate::security_assessment::{
    ConstraintEvidence, CoverageStatus, CoverageUnit, InventoryBackend, InventoryObservation,
    InventoryTarget, ObservationDiagnostic, ObservationLimits, PackageInstance, SourceKind,
    SourcePolicy, normalize_name,
};
use cap_std::fs::Dir;
use pep440_rs::{Version, VersionSpecifiers};
use pep508_rs::{MarkerWarningKind, Requirement, VersionOrUrl};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedRegistryBinding {
    pub source_id: String,
    pub auth_scope_id: String,
    pub registry_url: String,
}
#[derive(Debug, Clone)]
pub struct ProvenanceRequest {
    pub trusted_uv: PathBuf,
    /// Canonical, operator-controlled private cache directory.
    pub approved_cache_root: PathBuf,
    /// Canonical operator-owned authority paths, resolved before observation.
    pub authorized_roots: Vec<PathBuf>,
    pub limits: ObservationLimits,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ParentActivation {
    Proven,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParentEvidence {
    pub parent_instance_id: String,
    pub parent_name: String,
    pub parent_version: String,
    pub source_id: String,
    pub parent_node_id: String,
    pub child_node_id: String,
    pub requirements: Vec<ConstraintEvidence>,
    pub edge_marker: Option<String>,
    pub activation: ParentActivation,
    pub coverage: CoverageUnit,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceProvenance {
    pub instance_id: String,
    pub locked_paths: Option<Value>,
    pub parents: Vec<ParentEvidence>,
    pub coverage: CoverageUnit,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceObservation {
    pub inventory_id: String,
    pub lock_digest: Option<String>,
    pub backend: Option<Value>,
    pub instances: Vec<InstanceProvenance>,
    pub coverage: CoverageUnit,
    pub diagnostics: Vec<ObservationDiagnostic>,
}

pub fn observe_provenance(
    request: &ProvenanceRequest,
    inventory: &InventoryObservation,
    policy: &SourcePolicy,
    bindings: &[ApprovedRegistryBinding],
    deadline: Instant,
) -> ProvenanceObservation {
    let started = Instant::now();
    let mut result = ProvenanceObservation {
        inventory_id: inventory.inventory_id.clone(),
        lock_digest: None,
        backend: None,
        instances: vec![],
        coverage: CoverageUnit {
            requested: inventory.packages.len(),
            ..Default::default()
        },
        diagnostics: vec![],
    };
    if let Err(error) = observe(
        request,
        inventory,
        policy,
        bindings,
        deadline,
        started,
        &mut result,
    ) {
        result.coverage.status = CoverageStatus::Partial;
        result.coverage.complete = 0;
        result.coverage.partial = result.coverage.requested;
        result.coverage.reasons.push(error.code.clone());
        result.diagnostics.push(error);
        for entry in &mut result.instances {
            entry.coverage.status = CoverageStatus::Partial;
            entry.coverage.complete = 0;
            entry.coverage.partial = entry.coverage.requested;
            entry.coverage.reasons = result.coverage.reasons.clone();
        }
    }
    result
}

fn observe(
    request: &ProvenanceRequest,
    inventory: &InventoryObservation,
    policy: &SourcePolicy,
    bindings: &[ApprovedRegistryBinding],
    deadline: Instant,
    started: Instant,
    result: &mut ProvenanceObservation,
) -> Result<(), ObservationDiagnostic> {
    request.limits.validate()?;
    let deadline =
        deadline.min(started + std::time::Duration::from_millis(request.limits.total_timeout_ms));
    if inventory.packages.len() > request.limits.max_inventory_instances {
        return Err(diag(
            "E_SECURITY_GRAPH_LIMIT",
            "Installed graph inputs exceed the observation budget.",
        ));
    }
    result.instances = inventory
        .packages
        .iter()
        .map(|package| InstanceProvenance {
            instance_id: package.instance_id.clone(),
            locked_paths: None,
            parents: vec![],
            coverage: CoverageUnit {
                requested: 1,
                ..Default::default()
            },
        })
        .collect();
    policy.validate()?;
    check_deadline(deadline)?;
    let target = inventory
        .target
        .as_ref()
        .filter(|target| {
            target.backend == InventoryBackend::Uv && target.kind == InventoryTarget::Installed
        })
        .ok_or_else(|| {
            diag(
                "E_SECURITY_GRAPH_LAYOUT_UNSUPPORTED",
                "A proven installed uv project target is required.",
            )
        })?;
    let root = target
        .project_root
        .canonicalize()
        .map_err(|_| path_error())?;
    if root != target.project_root {
        return Err(diag(
            "E_SECURITY_GRAPH_INPUT_CHANGED",
            "The observed canonical project root changed during observation.",
        ));
    }
    // These are already canonical operator-owned authority roots. Resolving
    // them again after a filesystem replacement could silently widen access.
    if !request
        .authorized_roots
        .iter()
        .any(|allowed| allowed.is_absolute() && root.starts_with(allowed))
    {
        return Err(path_error());
    }
    let (dir, root_identity) = open_source_root(&root)?;
    let project = read_regular(&dir, "pyproject.toml", request.limits.max_metadata_bytes)?;
    let lock = read_regular(&dir, "uv.lock", request.limits.max_response_bytes)?;
    if target.project_digest.as_deref() != Some(crate::security::sha256_bytes(&project).as_str())
        || target.lock_digest.as_deref() != Some(crate::security::sha256_bytes(&lock).as_str())
    {
        return Err(diag(
            "E_SECURITY_GRAPH_INPUT_CHANGED",
            "Project or lock evidence differs from the observed installed target.",
        ));
    }
    let projected_project = project_projection(&project)?;
    let projected_lock = lock_projection(&lock)?;
    if projected_project.len() > request.limits.max_metadata_bytes
        || projected_lock.len() > request.limits.max_response_bytes
    {
        return Err(diag(
            "E_SECURITY_GRAPH_LIMIT",
            "The static graph projection exceeds the metadata budget.",
        ));
    }
    for binding in bindings {
        registry_url(&binding.registry_url)?;
    }
    let snapshot = PrivateSnapshot::create(&request.approved_cache_root)?;
    write_private(
        &snapshot.directory,
        "pyproject.toml",
        projected_project.as_bytes(),
    )?;
    write_private(&snapshot.directory, "uv.lock", projected_lock.as_bytes())?;
    if !snapshot.is_current() {
        return Err(path_error());
    }
    let snapshot_root = &snapshot.path;
    let executable = request.trusted_uv.canonicalize().map_err(|_| {
        diag(
            "E_SECURITY_GRAPH_BACKEND",
            "An explicitly trusted uv executable is required.",
        )
    })?;
    let mut graph = provenance_graph_bounded(&BoundedGraphRequest {
        executable: &executable,
        root: snapshot_root,
        directory: &snapshot.directory,
        max_output_bytes: request.limits.max_response_bytes,
        deadline,
    })
    .map_err(|error| diag(error.code, error.message))?;
    if !snapshot.is_current() {
        return Err(path_error());
    }
    // Remove ephemeral snapshot identities before semantic provenance is exposed.
    rebase(&mut graph.metadata, snapshot_root, &root);
    graph.lock = json!({"source":root.join("uv.lock"),"digest":crate::security::sha256_bytes(&lock),"graph_projection_digest":crate::security::sha256_bytes(projected_lock.as_bytes())});
    result.lock_digest = target.lock_digest.clone();
    result.backend = Some(graph.backend.clone());
    if read_regular(&dir, "pyproject.toml", request.limits.max_metadata_bytes)? != project
        || read_regular(&dir, "uv.lock", request.limits.max_response_bytes)? != lock
        || !source_root_unchanged(&root, &root_identity)
    {
        return Err(diag(
            "E_SECURITY_GRAPH_INPUT_CHANGED",
            "Project or lock changed during frozen graph observation.",
        ));
    }
    let nodes = graph
        .metadata
        .get("resolution")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            diag(
                "E_SECURITY_GRAPH_INVALID",
                "Frozen graph nodes are malformed.",
            )
        })?;
    let mut node_bindings = BTreeMap::new();
    for (id, node) in nodes {
        check_deadline(deadline)?;
        if let Some(package) = bind_node(node, inventory, policy, bindings) {
            node_bindings.insert(id.as_str(), package);
        }
    }
    let mut retained = 0usize;
    for entry in &mut result.instances {
        check_deadline(deadline)?;
        let package = inventory
            .packages
            .iter()
            .find(|package| package.instance_id == entry.instance_id)
            .unwrap();
        let target_nodes: Vec<_> = node_bindings
            .iter()
            .filter(|(_, candidate)| candidate.instance_id == package.instance_id)
            .map(|(id, _)| *id)
            .collect();
        if target_nodes.len() != 1 {
            partial(&mut entry.coverage, "E_SECURITY_GRAPH_BINDING_UNKNOWN");
        }
        let evidence = GraphEvidence {
            metadata: graph.metadata.clone(),
            backend: graph.backend.clone(),
            lock: graph.lock.clone(),
            packages: graph.packages.clone(),
        };
        match crate::why::analyze(evidence, &package.name) {
            Ok(paths)
                if reserve(
                    &mut retained,
                    &paths,
                    request.limits.max_retained_evidence_bytes,
                ) =>
            {
                if paths.get("complete").and_then(Value::as_bool) != Some(true) {
                    partial(&mut entry.coverage, "E_SECURITY_GRAPH_PATHS_INCOMPLETE");
                }
                entry.locked_paths = Some(paths)
            }
            Ok(_) => partial(&mut entry.coverage, "E_SECURITY_GRAPH_LIMIT"),
            Err(_) => partial(&mut entry.coverage, "E_SECURITY_GRAPH_PATHS_UNKNOWN"),
        }
        if target_nodes.len() == 1 {
            let target_id = target_nodes[0];
            for (parent_id, node) in nodes {
                check_deadline(deadline)?;
                let Some(edges) = node.get("dependencies").and_then(Value::as_array) else {
                    continue;
                };
                for edge in edges
                    .iter()
                    .filter(|edge| edge.get("id").and_then(Value::as_str) == Some(target_id))
                {
                    check_deadline(deadline)?;
                    let Some(parent) = node_bindings.get(parent_id.as_str()) else {
                        // Root project declarations remain in inventory.direct_constraints;
                        // an unmatched installed package parent must remain unknown.
                        if node.pointer("/source/registry").is_some() {
                            partial(&mut entry.coverage, "E_SECURITY_GRAPH_PARENT_UNKNOWN");
                        }
                        continue;
                    };
                    let marker = edge
                        .get("marker")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    let mut requirements = Vec::new();
                    let mut activation = if marker.is_none() {
                        ParentActivation::Proven
                    } else {
                        ParentActivation::Unknown
                    };
                    for constraint in &parent.requires_dist {
                        match parsed_requirement(&constraint.requirement) {
                            Ok(requirement) if requirement.name.as_ref() == package.name => {
                                if !requirement.marker.is_true()
                                    || matches!(
                                        requirement.version_or_url,
                                        Some(VersionOrUrl::Url(_))
                                    )
                                {
                                    activation = ParentActivation::Unknown;
                                }
                                if reserve(
                                    &mut retained,
                                    constraint,
                                    request.limits.max_retained_evidence_bytes,
                                ) {
                                    requirements.push(constraint.clone());
                                } else {
                                    activation = ParentActivation::Unknown;
                                    partial(&mut entry.coverage, "E_SECURITY_GRAPH_LIMIT");
                                }
                            }
                            Err(_) => {
                                activation = ParentActivation::Unknown;
                            }
                            _ => {}
                        }
                    }
                    let mut coverage = CoverageUnit {
                        requested: 1,
                        ..Default::default()
                    };
                    if requirements.is_empty() || activation == ParentActivation::Unknown {
                        activation = ParentActivation::Unknown;
                        partial(&mut coverage, "E_SECURITY_GRAPH_CONSTRAINT_UNKNOWN");
                        partial(&mut entry.coverage, "E_SECURITY_GRAPH_CONSTRAINT_UNKNOWN");
                    } else {
                        coverage.complete = 1;
                    }
                    let parent = ParentEvidence {
                        parent_instance_id: parent.instance_id.clone(),
                        parent_name: parent.name.clone(),
                        parent_version: parent.version.clone(),
                        source_id: parent.source.id.clone(),
                        parent_node_id: crate::security::sha256_bytes(parent_id.as_bytes()),
                        child_node_id: crate::security::sha256_bytes(target_id.as_bytes()),
                        requirements,
                        edge_marker: marker,
                        activation,
                        coverage,
                    };
                    // Requirements were charged above; this conservative second
                    // reservation also accounts for all wrapper/provenance bytes.
                    if reserve(
                        &mut retained,
                        &parent,
                        request.limits.max_retained_evidence_bytes,
                    ) {
                        entry.parents.push(parent);
                    } else {
                        partial(&mut entry.coverage, "E_SECURITY_GRAPH_LIMIT");
                    }
                }
            }
        }
        if entry.coverage.status == CoverageStatus::Complete {
            entry.coverage.complete = 1;
            result.coverage.complete += 1;
        } else {
            result.coverage.partial += 1;
            result.coverage.status = CoverageStatus::Partial;
        }
    }
    check_deadline(deadline)?;
    Ok(())
}

fn bind_node<'a>(
    node: &Value,
    inventory: &'a InventoryObservation,
    policy: &SourcePolicy,
    bindings: &[ApprovedRegistryBinding],
) -> Option<&'a PackageInstance> {
    if node.get("kind").and_then(Value::as_str) != Some("package") {
        return None;
    }
    let name = normalize_name(node.get("name")?.as_str()?).ok()?;
    let version = node.get("version")?.as_str()?.parse::<Version>().ok()?;
    let source = registry_url(node.pointer("/source/registry/url")?.as_str()?).ok()?;
    let approved: Vec<_> = bindings
        .iter()
        .filter(|binding| registry_url(&binding.registry_url).ok().as_ref() == Some(&source))
        .collect();
    if approved.len() != 1 {
        return None;
    }
    let binding = approved[0];
    let candidates: Vec<_> = inventory
        .packages
        .iter()
        .filter(|package| {
            package.name == name
                && package.version.parse::<Version>().ok().as_ref() == Some(&version)
                && package.source.id == binding.source_id
                && package.source.auth_scope_id == binding.auth_scope_id
                && matches!(
                    package.source.kind,
                    SourceKind::PublicRegistry | SourceKind::PrivateRegistry
                )
                && policy
                    .map_package_with_origin(
                        &package.name,
                        package.distribution_path.rsplit('/').next().unwrap_or(""),
                        package.source.kind,
                        package.origin_identity.as_deref(),
                    )
                    .is_ok_and(|current| current == package.package_source())
        })
        .collect();
    if candidates.len() == 1 {
        Some(candidates[0])
    } else {
        None
    }
}

fn registry_url(value: &str) -> Result<String, ObservationDiagnostic> {
    let parsed = reqwest::Url::parse(value).map_err(|_| layout_error())?;
    if !matches!(parsed.scheme(), "https" | "http")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || crate::support_bundle::redact_text(value) != value
    {
        return Err(layout_error());
    }
    Ok(parsed.as_str().trim_end_matches('/').into())
}
fn parsed_requirement(text: &str) -> Result<Requirement<reqwest::Url>, ()> {
    let mut uncertain = false;
    let mut reporter = |kind: MarkerWarningKind, _message: String| {
        uncertain |= kind != MarkerWarningKind::DeprecatedMarkerName;
    };
    // Url's parser does not expand process environment or inspect CWD. Capture
    // ignored-marker warnings rather than treating their simplified tree as a
    // proven unconditional requirement; raw parser messages are never emitted.
    let requirement =
        Requirement::<reqwest::Url>::parse_reporter(text, Path::new("/"), &mut reporter)
            .map_err(|_| ())?;
    if uncertain { Err(()) } else { Ok(requirement) }
}

fn requirement_list(value: &toml::Value) -> Result<toml::Value, ObservationDiagnostic> {
    let values = value.as_array().ok_or_else(layout_error)?;
    for value in values {
        let text = value.as_str().ok_or_else(layout_error)?;
        let requirement = parsed_requirement(text).map_err(|_| layout_error())?;
        if matches!(requirement.version_or_url, Some(VersionOrUrl::Url(_)))
            || crate::support_bundle::redact_text(text) != text
        {
            return Err(layout_error());
        }
    }
    Ok(value.clone())
}
fn project_projection(bytes: &[u8]) -> Result<String, ObservationDiagnostic> {
    let original: toml::Value = std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| toml::from_str(text).ok())
        .ok_or_else(layout_error)?;
    let project = original
        .get("project")
        .and_then(toml::Value::as_table)
        .ok_or_else(layout_error)?;
    if project
        .get("dynamic")
        .is_some_and(|value| !value.as_array().is_some_and(Vec::is_empty))
    {
        return Err(layout_error());
    }
    let name = project
        .get("name")
        .and_then(toml::Value::as_str)
        .ok_or_else(layout_error)?;
    normalize_name(name)?;
    project
        .get("version")
        .and_then(toml::Value::as_str)
        .and_then(|version| version.parse::<Version>().ok())
        .ok_or_else(layout_error)?;
    if let Some(value) = project.get("requires-python") {
        value
            .as_str()
            .and_then(|text| text.parse::<VersionSpecifiers>().ok())
            .ok_or_else(layout_error)?;
    }
    if original
        .get("build-system")
        .and_then(|value| value.get("backend-path"))
        .is_some()
    {
        return Err(layout_error());
    }
    // Do not copy arbitrary tool configuration, build-system paths, credentials
    // or metadata files. Reject workspace/source overrides before projection.
    if let Some(uv) = original
        .get("tool")
        .and_then(|tool| tool.get("uv"))
        .and_then(toml::Value::as_table)
    {
        if uv
            .keys()
            .any(|key| !matches!(key.as_str(), "workspace" | "package" | "managed"))
        {
            return Err(layout_error());
        }
        if uv.get("managed").and_then(toml::Value::as_bool) == Some(false) {
            return Err(layout_error());
        }
        if let Some(workspace) = uv.get("workspace") {
            let members = workspace.get("members");
            if !workspace.as_table().is_some_and(|table| {
                table.keys().all(|key| key == "members")
                    && members.is_none_or(|members| members.as_array().is_some_and(Vec::is_empty))
            }) {
                return Err(layout_error());
            }
        }
    }
    let mut projected = toml::map::Map::new();
    for key in ["name", "version", "requires-python"] {
        if let Some(value) = project.get(key) {
            projected.insert(key.into(), value.clone());
        }
    }
    if let Some(value) = project.get("dependencies") {
        projected.insert("dependencies".into(), requirement_list(value)?);
    }
    if let Some(extras) = project.get("optional-dependencies") {
        let mut values = toml::map::Map::new();
        for (name, value) in extras.as_table().ok_or_else(layout_error)? {
            normalize_name(name)?;
            values.insert(name.clone(), requirement_list(value)?);
        }
        projected.insert("optional-dependencies".into(), toml::Value::Table(values));
    }
    let mut output = toml::map::Map::new();
    output.insert("project".into(), toml::Value::Table(projected));
    if let Some(groups) = original.get("dependency-groups") {
        let mut values = toml::map::Map::new();
        for (name, value) in groups.as_table().ok_or_else(layout_error)? {
            normalize_name(name)?;
            values.insert(name.clone(), requirement_list(value)?);
        }
        output.insert("dependency-groups".into(), toml::Value::Table(values));
    }
    let mut workspace = toml::map::Map::new();
    workspace.insert("members".into(), toml::Value::Array(vec![]));
    let mut uv = toml::map::Map::new();
    uv.insert("workspace".into(), toml::Value::Table(workspace));
    let mut tool = toml::map::Map::new();
    tool.insert("uv".into(), toml::Value::Table(uv));
    output.insert("tool".into(), toml::Value::Table(tool));
    serialize_projection(&output)
}
fn lock_source(value: &toml::Value) -> Result<(), ObservationDiagnostic> {
    let source = value.as_table().ok_or_else(layout_error)?;
    if source.len() != 1 {
        return Err(layout_error());
    }
    if let Some(url) = source.get("registry").and_then(toml::Value::as_str) {
        registry_url(url)?;
        return Ok(());
    }
    if ["virtual", "editable"]
        .iter()
        .any(|key| source.get(*key).and_then(toml::Value::as_str) == Some("."))
    {
        return Ok(());
    }
    Err(layout_error())
}
fn lock_dependencies(value: &toml::Value) -> Result<(), ObservationDiagnostic> {
    for dependency in value.as_array().ok_or_else(layout_error)? {
        let table = dependency.as_table().ok_or_else(layout_error)?;
        if table.keys().any(|key| {
            !matches!(
                key.as_str(),
                "name" | "version" | "source" | "marker" | "extras"
            )
        }) {
            return Err(layout_error());
        }
        normalize_name(
            table
                .get("name")
                .and_then(toml::Value::as_str)
                .ok_or_else(layout_error)?,
        )?;
        if let Some(version) = table.get("version") {
            version
                .as_str()
                .and_then(|text| text.parse::<Version>().ok())
                .ok_or_else(layout_error)?;
        }
        if let Some(extras) = table.get("extras") {
            for extra in extras.as_array().ok_or_else(layout_error)? {
                normalize_name(extra.as_str().ok_or_else(layout_error)?)?;
            }
        }
        if let Some(source) = table.get("source") {
            lock_source(source)?;
        }
        if crate::support_bundle::redact_text(&dependency.to_string()) != dependency.to_string() {
            return Err(layout_error());
        }
    }
    Ok(())
}
fn lock_projection(bytes: &[u8]) -> Result<String, ObservationDiagnostic> {
    let original: toml::Value = std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| toml::from_str(text).ok())
        .ok_or_else(layout_error)?;
    if original.get("version").and_then(toml::Value::as_integer) != Some(1) {
        return Err(layout_error());
    }
    original
        .get("requires-python")
        .and_then(toml::Value::as_str)
        .and_then(|text| text.parse::<VersionSpecifiers>().ok())
        .ok_or_else(layout_error)?;
    let mut output = toml::map::Map::new();
    for key in [
        "version",
        "revision",
        "requires-python",
        "resolution-markers",
        "supported-markers",
        "conflicts",
    ] {
        if let Some(value) = original.get(key) {
            output.insert(key.into(), value.clone());
        }
    }
    let mut packages = vec![];
    for package in original
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or_else(layout_error)?
    {
        let mut value = toml::map::Map::new();
        for key in ["name", "version", "source"] {
            value.insert(
                key.into(),
                package.get(key).ok_or_else(layout_error)?.clone(),
            );
        }
        normalize_name(value["name"].as_str().ok_or_else(layout_error)?)?;
        value["version"]
            .as_str()
            .and_then(|text| text.parse::<Version>().ok())
            .ok_or_else(layout_error)?;
        lock_source(&value["source"])?;
        if let Some(dependencies) = package.get("dependencies") {
            lock_dependencies(dependencies)?;
            value.insert("dependencies".into(), dependencies.clone());
        }
        for key in ["optional-dependencies", "dev-dependencies"] {
            if let Some(groups) = package.get(key) {
                for dependencies in groups.as_table().ok_or_else(layout_error)?.values() {
                    lock_dependencies(dependencies)?;
                }
                value.insert(key.into(), groups.clone());
            }
        }
        packages.push(toml::Value::Table(value));
    }
    output.insert("package".into(), toml::Value::Array(packages));
    serialize_projection(&output)
}
fn serialize_projection(
    output: &toml::map::Map<String, toml::Value>,
) -> Result<String, ObservationDiagnostic> {
    let text = toml::to_string(output).map_err(|_| layout_error())?;
    // Reject recognized credential-bearing data rather than rewriting source
    // identity or requirement semantics while constructing the snapshot.
    if crate::support_bundle::redact_text(&text) != text {
        return Err(layout_error());
    }
    Ok(text)
}

#[cfg(unix)]
fn open_source_root(root: &Path) -> Result<(Dir, std::fs::Metadata), ObservationDiagnostic> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(root)
        .map_err(|_| path_error())?;
    let identity = file.metadata().map_err(|_| path_error())?;
    if !identity.is_dir() {
        return Err(path_error());
    }
    Ok((Dir::from_std_file(file), identity))
}
#[cfg(not(unix))]
fn open_source_root(_root: &Path) -> Result<(Dir, std::fs::Metadata), ObservationDiagnostic> {
    Err(diag(
        "E_SECURITY_GRAPH_LAYOUT_UNSUPPORTED",
        "This platform cannot prove the required no-follow directory and private-cache profile.",
    ))
}
#[cfg(unix)]
fn source_root_unchanged(root: &Path, expected: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(root).is_ok_and(|actual| {
        actual.is_dir()
            && !actual.file_type().is_symlink()
            && actual.dev() == expected.dev()
            && actual.ino() == expected.ino()
    })
}
#[cfg(not(unix))]
fn source_root_unchanged(_root: &Path, _expected: &std::fs::Metadata) -> bool {
    false
}

fn read_regular(dir: &Dir, name: &str, limit: usize) -> Result<Vec<u8>, ObservationDiagnostic> {
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = dir.open_with(name, &options).map_err(|_| path_error())?;
    if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
        return Err(path_error());
    }
    let mut bytes = vec![];
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| path_error())?;
    if bytes.len() > limit {
        return Err(diag(
            "E_SECURITY_GRAPH_LIMIT",
            "Graph inputs exceed the metadata budget.",
        ));
    }
    Ok(bytes)
}
struct PrivateSnapshot {
    cache: Dir,
    cache_path: PathBuf,
    cache_identity: std::fs::Metadata,
    name: String,
    directory: Dir,
    identity: std::fs::Metadata,
    path: PathBuf,
}
impl PrivateSnapshot {
    fn create(path: &Path) -> Result<Self, ObservationDiagnostic> {
        if !path.is_absolute() || path.canonicalize().map_err(|_| path_error())? != path {
            return Err(path_error());
        }
        let (cache, cache_identity) = open_source_root(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if cache_identity.permissions().mode() & 0o077 != 0 {
                return Err(path_error());
            }
        }
        let name = format!("security-graph-{}", uuid::Uuid::new_v4());
        create_private_directory(&cache, &name)?;
        let mut options = cap_std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = cache
            .open_with(&name, &options)
            .map_err(|_| path_error())?
            .into_std();
        let identity = file.metadata().map_err(|_| path_error())?;
        let directory = Dir::from_std_file(file);
        let snapshot = Self {
            cache,
            cache_path: path.into(),
            cache_identity,
            name: name.clone(),
            directory,
            identity,
            path: path.join(name),
        };
        if !snapshot.is_current() {
            return Err(path_error());
        }
        create_private_directory(&snapshot.directory, "cache")?;
        Ok(snapshot)
    }
    fn is_current(&self) -> bool {
        source_root_unchanged(&self.cache_path, &self.cache_identity)
            && scoped_directory_unchanged(&self.cache, &self.name, &self.identity)
    }
}
impl Drop for PrivateSnapshot {
    fn drop(&mut self) {
        if scoped_directory_unchanged(&self.cache, &self.name, &self.identity) {
            let _ = self.cache.remove_dir_all(&self.name);
        }
    }
}
fn create_private_directory(parent: &Dir, name: &str) -> Result<(), ObservationDiagnostic> {
    #[cfg(unix)]
    let mut builder = cap_std::fs::DirBuilder::new();
    #[cfg(not(unix))]
    let builder = cap_std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use cap_std::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    parent
        .create_dir_with(name, &builder)
        .map_err(|_| path_error())
}
#[cfg(unix)]
fn scoped_directory_unchanged(parent: &Dir, name: &str, expected: &std::fs::Metadata) -> bool {
    use cap_std::fs::MetadataExt as CapMetadataExt;
    use std::os::unix::fs::MetadataExt as StdMetadataExt;
    parent.symlink_metadata(name).is_ok_and(|actual| {
        actual.is_dir()
            && !actual.file_type().is_symlink()
            && actual.dev() == expected.dev()
            && actual.ino() == expected.ino()
    })
}
#[cfg(not(unix))]
fn scoped_directory_unchanged(_parent: &Dir, _name: &str, _expected: &std::fs::Metadata) -> bool {
    false
}
fn write_private(parent: &Dir, name: &str, bytes: &[u8]) -> Result<(), ObservationDiagnostic> {
    let mut options = cap_std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    parent
        .open_with(name, &options)
        .and_then(|mut file| file.write_all(bytes))
        .map_err(|_| path_error())
}

fn rebase(value: &mut Value, snapshot: &Path, root: &Path) {
    let from = snapshot.to_string_lossy();
    let to = root.to_string_lossy();
    fn replace(value: &mut Value, from: &str, to: &str) {
        match value {
            Value::String(value) => *value = value.replace(from, to),
            Value::Array(values) => {
                for value in values {
                    replace(value, from, to)
                }
            }
            Value::Object(values) => {
                let old = std::mem::take(values);
                for (key, mut value) in old {
                    replace(&mut value, from, to);
                    values.insert(key.replace(from, to), value);
                }
            }
            _ => {}
        }
    }
    replace(value, &from, &to);
}
fn reserve<T: Serialize>(retained: &mut usize, value: &T, limit: usize) -> bool {
    match serde_json::to_vec(value) {
        Ok(bytes) if bytes.len() <= limit.saturating_sub(*retained) => {
            *retained += bytes.len();
            true
        }
        _ => false,
    }
}
fn partial(coverage: &mut CoverageUnit, code: &str) {
    coverage.status = CoverageStatus::Partial;
    coverage.complete = 0;
    coverage.partial = coverage.requested;
    if !coverage.reasons.iter().any(|reason| reason == code) {
        coverage.reasons.push(code.into());
    }
}
fn check_deadline(deadline: Instant) -> Result<(), ObservationDiagnostic> {
    if Instant::now() >= deadline {
        Err(diag(
            "E_SECURITY_GRAPH_LIMIT",
            "The shared graph deadline was exhausted.",
        ))
    } else {
        Ok(())
    }
}
fn layout_error() -> ObservationDiagnostic {
    diag(
        "E_SECURITY_GRAPH_LAYOUT_UNSUPPORTED",
        "This layout cannot prove a static secret-free confined frozen graph.",
    )
}
fn path_error() -> ObservationDiagnostic {
    diag(
        "E_SECURITY_GRAPH_PATH",
        "Graph paths must remain inside explicit project or private cache authority.",
    )
}
fn diag(code: &str, message: &str) -> ObservationDiagnostic {
    ObservationDiagnostic::new(code, message)
}
