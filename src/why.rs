//! Backend-owned, read-only dependency provenance. Never resolve dependencies here.
mod native;
use crate::backend::GraphEvidence;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Debug)]
pub struct WhyError {
    pub code: &'static str,
    pub message: &'static str,
}
impl From<crate::backend::BackendError> for WhyError {
    fn from(error: crate::backend::BackendError) -> Self {
        Self {
            code: error.code,
            message: error.message,
        }
    }
}
fn invalid() -> WhyError {
    WhyError {
        code: "E_WHY_GRAPH_INVALID",
        message: "Backend graph evidence is incomplete or malformed; use a supported backend and regenerate its lock explicitly.",
    }
}
fn name(value: &str) -> Option<String> {
    if value.is_empty()
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || "-_.".contains(ch))
        || !value.chars().next()?.is_ascii_alphanumeric()
        || !value.chars().last()?.is_ascii_alphanumeric()
    {
        return None;
    }
    Some(
        value
            .split(['-', '_', '.'])
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join("-")
            .to_ascii_lowercase(),
    )
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind<'a> {
    Package,
    Workspace,
    Script,
    Extra(&'a str),
    Group(&'a str),
    Unknown,
}
fn kind(value: &Value) -> Kind<'_> {
    match value.as_str() {
        Some("package") => Kind::Package,
        Some("workspace") => Kind::Workspace,
        Some("script") => Kind::Script,
        _ => {
            if let Some(map) = value.as_object().filter(|map| map.len() == 1) {
                if let Some(extra) = map
                    .get("extra")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                {
                    return Kind::Extra(extra);
                }
                if let Some(group) = map
                    .get("group")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                {
                    return Kind::Group(group);
                }
            }
            Kind::Unknown
        }
    }
}
struct Edge<'a> {
    id: &'a str,
    marker: Option<&'a str>,
}
struct Node<'a> {
    raw: &'a Value,
    name: &'a str,
    version: Option<&'a str>,
    kind: Kind<'a>,
    edges: Vec<Edge<'a>>,
    public: Value,
}
fn note(notes: &mut Vec<Value>, code: &str, message: &str) {
    if !notes.iter().any(|note| note["code"] == code) {
        notes.push(json!({"level":"warning","code":code,"message":message}));
    }
}

pub fn explain(root: &Path, package: &str) -> Result<Value, WhyError> {
    explain_scoped(root, package, Vec::new())
}
fn explain_scoped(
    root: &Path,
    package: &str,
    roots: Vec<std::path::PathBuf>,
) -> Result<Value, WhyError> {
    let package = name(package).ok_or(WhyError {
        code: "E_WHY_ARGUMENT",
        message: "Provide one distribution name, without version specifiers or extras.",
    })?;
    let evidence = if crate::backend::native_selected() {
        native::graph(root, &roots)?
    } else {
        crate::backend::provenance_graph_scoped(root, roots)?
    };
    analyze(evidence, &package)
}

fn analyze(evidence: GraphEvidence, package: &str) -> Result<Value, WhyError> {
    let raw = evidence.metadata["resolution"]
        .as_object()
        .ok_or_else(invalid)?;
    if raw.len() > 10000 {
        return Err(invalid());
    }
    let mut complete = evidence.backend["name"] != "native";
    let mut notes = Vec::new();
    if !complete {
        note(
            &mut notes,
            "W_WHY_NATIVE_PROVENANCE",
            "Native locks omit selected marker/extra/group state; declaration-derived provenance is partial.",
        );
    }
    let mut locked_pairs = BTreeSet::new();
    for package in &evidence.packages {
        let normalized = package["name"]
            .as_str()
            .and_then(name)
            .ok_or_else(invalid)?;
        locked_pairs.insert((normalized, package["version"].as_str()));
    }
    let mut nodes = BTreeMap::new();
    for (id, value) in raw {
        if id.is_empty() || id.len() > 8192 {
            return Err(invalid());
        }
        let kind = kind(&value["kind"]);
        let node_name = value
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(match kind {
                Kind::Script => "script",
                _ => "workspace",
            });
        if name(node_name).is_none() {
            return Err(invalid());
        }
        let version = match value.get("version") {
            None | Some(Value::Null) => None,
            Some(Value::String(version))
                if crate::pep440::Pep440Version::parse(version).is_some() =>
            {
                Some(version.as_str())
            }
            _ => return Err(invalid()),
        };
        if kind == Kind::Package
            && (value.get("name").and_then(Value::as_str).is_none() || !value["source"].is_object())
        {
            return Err(invalid());
        }
        if kind == Kind::Package
            && evidence.backend["name"] == "uv"
            && !locked_pairs.contains(&(name(node_name).unwrap(), version))
        {
            return Err(invalid());
        }
        if kind == Kind::Unknown || (kind == Kind::Package && version.is_none()) {
            complete = false;
            note(
                &mut notes,
                "W_WHY_PROVENANCE_UNKNOWN",
                "Some backend nodes have unknown kind or version evidence.",
            );
        }
        let mut edges = Vec::new();
        for edge in value["dependencies"].as_array().ok_or_else(invalid)? {
            let id = edge["id"].as_str().ok_or_else(invalid)?;
            let marker = match edge.get("marker") {
                None | Some(Value::Null) => None,
                Some(Value::String(marker)) => Some(marker.as_str()),
                _ => return Err(invalid()),
            };
            edges.push(Edge { id, marker });
        }
        edges.sort_by_key(|edge| (edge.id, edge.marker));
        edges.dedup_by(|left, right| left.id == right.id && left.marker == right.marker);
        let public_kind = match kind {
            Kind::Package => json!("package"),
            Kind::Workspace => json!("workspace"),
            Kind::Script => json!("script"),
            Kind::Extra(extra) => json!({"extra":extra}),
            Kind::Group(group) => json!({"group":group}),
            Kind::Unknown => json!("unknown"),
        };
        let public = json!({"id":hex::encode(Sha256::digest(id.as_bytes())),"name":node_name,"version":version,"kind":public_kind});
        nodes.insert(
            id.as_str(),
            Node {
                raw: value,
                name: node_name,
                version,
                kind,
                edges,
                public,
            },
        );
    }
    for node in nodes.values() {
        for edge in &node.edges {
            if !nodes.contains_key(edge.id) {
                return Err(invalid());
            }
        }
    }
    let members = evidence.metadata["members"]
        .as_array()
        .ok_or_else(invalid)?;
    let mut member_ids = BTreeSet::new();
    let mut roots = BTreeSet::new();
    for member in members {
        let id = member["id"].as_str().ok_or_else(invalid)?;
        member_ids.insert(id);
        roots.insert(id);
    }
    for key in ["workspace", "script"] {
        if let Some(value) = evidence.metadata.get(key) {
            roots.insert(value["id"].as_str().ok_or_else(invalid)?);
        }
    }
    let mut workspace_roots = member_ids;
    if let Some(id) = evidence
        .metadata
        .pointer("/workspace/id")
        .and_then(Value::as_str)
    {
        workspace_roots.insert(id);
    }
    let mut choices: Vec<_> = roots.iter().copied().collect();
    while let Some(id) = choices.pop() {
        let node = nodes.get(id).ok_or_else(invalid)?;
        for key in ["optional_dependencies", "dependency_groups"] {
            if let Some(items) = node.raw.get(key) {
                for item in items.as_array().ok_or_else(invalid)? {
                    let child = item["id"].as_str().ok_or_else(invalid)?;
                    if workspace_roots.contains(id) {
                        workspace_roots.insert(child);
                    }
                    if roots.insert(child) {
                        choices.push(child);
                    }
                }
            }
        }
    }
    let targets: BTreeSet<_> = nodes
        .iter()
        .filter(|(_, node)| {
            node.kind == Kind::Package && name(node.name).as_deref() == Some(package)
        })
        .map(|(id, _)| *id)
        .collect();
    let locked: Vec<_> = evidence
        .packages
        .iter()
        .filter(|item| item["name"].as_str().and_then(name).as_deref() == Some(package))
        .collect();
    if targets.is_empty() && locked.is_empty() {
        return Err(WhyError {
            code: "E_WHY_PACKAGE_NOT_FOUND",
            message: "The package is absent from the selected backend graph and lock. Check its distribution name or update the lock explicitly.",
        });
    }
    let mut paths = BTreeSet::new();
    let mut covered = BTreeSet::new();
    let mut expanded = 0;
    let mut output_nodes = 0;
    'roots: for root in &roots {
        let root_node = nodes.get(root).ok_or_else(invalid)?;
        let mut stack = vec![(vec![*root], Vec::<Option<&str>>::new())];
        while let Some((chain, markers)) = stack.pop() {
            expanded += 1;
            if expanded > 100000
                || chain.len() > 256
                || paths.len() >= 1000
                || output_nodes > 20000
                || stack.len() > 10000
            {
                complete = false;
                note(
                    &mut notes,
                    "W_WHY_GRAPH_LIMIT",
                    "Graph traversal reached its documented bound; returned paths are incomplete.",
                );
                break 'roots;
            }
            let id = *chain.last().unwrap();
            let node = &nodes[id];
            if targets.contains(id) {
                covered.insert(id);
                let mut provenance = BTreeSet::new();
                let mut packages = 0usize;
                let mut owner_base = false;
                for id in &chain {
                    let node = &nodes[id];
                    match node.kind {
                        Kind::Package => {
                            packages += 1;
                            if node.name == root_node.name
                                && node.version == root_node.version
                                && node.raw.get("source") == root_node.raw.get("source")
                            {
                                owner_base = true;
                            }
                        }
                        Kind::Extra(_) => {
                            provenance.insert("optional-extra");
                        }
                        Kind::Group(_) => {
                            provenance.insert("dependency-group");
                        }
                        Kind::Unknown => {
                            provenance.insert("unknown");
                        }
                        _ => {}
                    }
                }
                if workspace_roots.contains(root) || root_node.kind == Kind::Workspace {
                    provenance.insert("workspace");
                }
                let offset = usize::from(
                    root_node.kind == Kind::Package
                        || (matches!(root_node.kind, Kind::Extra(_)) && owner_base),
                );
                provenance.insert(if packages.saturating_sub(offset) <= 1 {
                    "direct"
                } else {
                    "transitive"
                });
                let chain: Vec<_> = chain.iter().map(|id| nodes[id].public.clone()).collect();
                let path = json!({"chain":chain,"markers":markers,"provenance":provenance});
                if paths.insert(path.to_string()) {
                    output_nodes += chain.len();
                }
            }
            for edge in node.edges.iter().rev() {
                if !chain.contains(&edge.id) {
                    let mut next = chain.clone();
                    next.push(edge.id);
                    let mut next_markers = markers.clone();
                    next_markers.push(edge.marker);
                    stack.push((next, next_markers));
                }
            }
        }
    }
    let mut paths: Vec<Value> = paths
        .into_iter()
        .map(|path| serde_json::from_str(&path).unwrap())
        .collect();
    // Keep each backend identity, including versions absent from reachable paths.
    let mut represented = BTreeMap::<Option<&str>, usize>::new();
    let mut unknown = Vec::new();
    for id in &targets {
        let node = &nodes[id];
        *represented.entry(node.version).or_default() += 1;
        if !covered.contains(id) {
            unknown.push(node.public.clone());
        }
    }
    for item in locked {
        let count = represented.entry(item["version"].as_str()).or_default();
        if *count > 0 {
            *count -= 1;
        } else {
            unknown.push(
                json!({"id":null,"name":item["name"],"version":item["version"],"kind":"package"}),
            );
        }
    }
    if !unknown.is_empty() {
        complete = false;
        note(
            &mut notes,
            "W_WHY_PROVENANCE_UNKNOWN",
            "Some locked package identities have no known declaration path; their provenance is unknown.",
        );
        for node in unknown {
            paths.push(json!({"chain":[node],"markers":[],"provenance":["unknown"]}));
        }
    }
    if evidence
        .metadata
        .pointer("/conflicts/sets")
        .and_then(Value::as_array)
        .is_some_and(|sets| !sets.is_empty())
    {
        note(
            &mut notes,
            "W_WHY_ALTERNATIVE_SELECTIONS",
            "The backend records mutually exclusive selections; these paths are alternatives, not a jointly installed environment.",
        );
    }
    notes.sort_by_key(|note| note["code"].as_str().unwrap().to_string());
    Ok(crate::support_bundle::redact_json(
        &json!({"schema_version":1,"package":package,"scope":"locked_dependency_graph","activation":"not_evaluated","backend":evidence.backend,"lock":evidence.lock,"complete":complete,"paths":paths,"diagnostics":notes}),
    ))
}

pub fn text(result: &Value) -> String {
    let mut lines = vec![format!(
        "{}: {} dependency chain(s) [{}]",
        result["package"].as_str().unwrap_or("?"),
        result["paths"].as_array().map_or(0, Vec::len),
        result["backend"]["name"].as_str().unwrap_or("unknown")
    )];
    if let Some(paths) = result["paths"].as_array() {
        for path in paths {
            let chain = path["chain"]
                .as_array()
                .unwrap()
                .iter()
                .map(|node| {
                    let mut label = node["name"].as_str().unwrap_or("?").to_string();
                    if let Some(extra) = node["kind"]["extra"].as_str() {
                        label += &format!("[{extra}]");
                    }
                    if let Some(group) = node["kind"]["group"].as_str() {
                        label += &format!(":{group}");
                    }
                    label
                })
                .collect::<Vec<_>>()
                .join(" -> ");
            lines.push(format!("  {chain}"));
        }
    }
    if result["complete"] == false {
        lines.push("Some provenance is unavailable; inspect JSON diagnostics.".into());
    }
    lines.join("\n")
}

pub(crate) fn call(args: Value, roots: Vec<std::path::PathBuf>) -> Result<String, String> {
    let result = args["package"]
        .as_str()
        .ok_or(WhyError {
            code: "E_WHY_ARGUMENT",
            message: "Provide a distribution name in package.",
        })
        .and_then(|package| {
            std::env::current_dir()
                .map_err(|_| WhyError {
                    code: "E_WHY_PROJECT",
                    message: "Cannot locate the current project.",
                })
                .and_then(|root| explain_scoped(&root, package, roots))
        });
    result.map(|value|value.to_string()).map_err(|error|json!({"status":"error","diagnostics":[{"level":"error","code":error.code,"message":error.message}]}).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn evidence(resolution: Value) -> GraphEvidence {
        let packages = resolution
            .as_object()
            .unwrap()
            .values()
            .filter(|node| node["kind"] == "package")
            .map(|node| json!({"name":node["name"],"version":node["version"]}))
            .collect();
        GraphEvidence {
            metadata: json!({"resolution":resolution,"members":[],"workspace":{"id":"root"}}),
            backend: json!({"name":"uv","version":"0.12.13"}),
            lock: json!({"digest":"fixture"}),
            packages,
        }
    }
    fn package(name: &str, version: &str, dependencies: Value) -> Value {
        json!({"name":name,"version":version,"kind":"package","source":{"registry":{"url":"https://example.org/simple"}},"dependencies":dependencies})
    }
    #[test]
    fn deduplication_preserves_multiple_versions_and_edges() {
        let graph = json!({"root":{"kind":"workspace","dependencies":[{"id":"one"},{"id":"one"},{"id":"two"}]},"one":package("Target","1",json!([])),"two":package("target","2",json!([]))});
        let result = analyze(evidence(graph), "target").unwrap();
        assert_eq!(result["paths"].as_array().unwrap().len(), 2);
        assert_eq!(result["complete"], true);
    }
    #[test]
    fn unknown_kinds_and_unreachable_packages_remain_partial() {
        let graph = json!({"root":{"kind":"workspace","dependencies":[{"id":"future"}]},"future":{"kind":"future-build","dependencies":[{"id":"target"}]},"target":package("target","1",json!([]))});
        let result = analyze(evidence(graph), "target").unwrap();
        assert_eq!(result["complete"], false);
        assert!(
            result["paths"][0]["provenance"]
                .as_array()
                .unwrap()
                .contains(&json!("unknown"))
        );
        let graph = json!({"root":{"kind":"workspace","dependencies":[]},"target":package("target","1",json!([]))});
        let result = analyze(evidence(graph), "target").unwrap();
        assert_eq!(result["paths"][0]["provenance"], json!(["unknown"]));
        assert_eq!(result["complete"], false);
    }
    #[test]
    fn mixed_reachable_and_missing_variants_remain_explicit() {
        let graph = json!({"root":{"kind":"workspace","dependencies":[{"id":"one"}]},"one":package("target","1",json!([])),"two":package("target","2",json!([]))});
        let mut samples = vec![evidence(graph)];
        let mut missing = evidence(
            json!({"root":{"kind":"workspace","dependencies":[{"id":"one"}]},"one":package("target","1",json!([]))}),
        );
        missing
            .packages
            .push(json!({"name":"target","version":"2"}));
        samples.push(missing);
        for sample in samples {
            let result = analyze(sample, "target").unwrap();
            assert_eq!(result["complete"], false);
            let paths = result["paths"].as_array().unwrap();
            assert_eq!(paths.len(), 2);
            assert!(
                paths
                    .iter()
                    .any(|path| path["provenance"] == json!(["unknown"])
                        && path["chain"][0]["version"] == "2")
            );
        }
    }
    #[test]
    fn malformed_links_and_traversal_limits_are_explicit() {
        let graph = json!({"root":{"kind":"workspace","dependencies":[{"id":"missing"}]}});
        assert_eq!(
            analyze(evidence(graph), "target").unwrap_err().code,
            "E_WHY_GRAPH_INVALID"
        );
        let mut graph = serde_json::Map::new();
        graph.insert(
            "root".into(),
            json!({"kind":"workspace","dependencies":[{"id":"p0"}]}),
        );
        for index in 0..260 {
            graph.insert(
                format!("p{index}"),
                package(
                    &format!("p{index}"),
                    "1",
                    if index == 259 {
                        json!([])
                    } else {
                        json!([{"id":format!("p{}",index+1)}])
                    },
                ),
            );
        }
        let result = analyze(evidence(Value::Object(graph)), "p259").unwrap();
        assert_eq!(result["complete"], false);
        assert!(
            result["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .any(|note| note["code"] == "W_WHY_GRAPH_LIMIT")
        );
    }
}
