//! Legacy native locks have a graph, but only current declarations supply roots.
use super::{WhyError, invalid, name};
use crate::backend::GraphEvidence;
use crate::project::Project;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

fn links(
    requirements: &[String],
    packages: &BTreeMap<String, (String, String)>,
) -> Result<Vec<Value>, WhyError> {
    let mut edges = Vec::new();
    for requirement in requirements {
        let requirement: crate::resolver::Requirement =
            requirement.parse().map_err(|_| invalid())?;
        let normalized = name(&requirement.name).ok_or_else(invalid)?;
        if let Some((id, version)) = packages.get(&normalized)
            && requirement.is_satisfied_by(version)
        {
            edges.push(json!({"id":id,"marker":requirement.marker}));
        }
    }
    Ok(edges)
}

pub(super) fn graph(start: &Path) -> Result<GraphEvidence, WhyError> {
    let (root, projects) = if let Some(workspace) =
        crate::workspace::Workspace::discover_root(start).map_err(|_| invalid())?
    {
        let root = workspace.root.root().to_path_buf();
        let mut projects = vec![workspace.root];
        projects.extend(workspace.members);
        (root, projects)
    } else {
        match Project::discover(start) {
            Ok(project) => (project.root().to_path_buf(), vec![project]),
            Err(crate::project::ProjectError::NotFound(_)) => (start.to_path_buf(), vec![]),
            Err(_) => return Err(invalid()),
        }
    };
    let path = root.join("pybun.lockb");
    let bytes=std::fs::read(&path).map_err(|_|WhyError{code:"E_WHY_LOCK_MISSING",message:"The native lock is unavailable. Run native install or select the uv backend for uv.lock projects."})?;
    let lock = crate::lockfile::Lockfile::from_bytes(&bytes).map_err(|_| invalid())?;
    let mut packages = BTreeMap::new();
    for package in lock.packages.values() {
        let normalized = name(&package.name).ok_or_else(invalid)?;
        if packages
            .insert(
                normalized.clone(),
                (format!("package:{normalized}"), package.version.clone()),
            )
            .is_some()
        {
            return Err(invalid());
        }
    }
    let mut resolution = Map::new();
    let mut inventory = Vec::new();
    for package in lock.packages.values() {
        let normalized = name(&package.name).ok_or_else(invalid)?;
        let id = &packages[&normalized].0;
        resolution.insert(id.clone(),json!({"kind":"package","name":normalized,"version":package.version,"source":{"native":"lock"},"dependencies":links(&package.dependencies,&packages)?}));
        inventory.push(json!({"name":normalized,"version":package.version}));
    }
    resolution.insert(
        "workspace".into(),
        json!({"kind":"workspace","dependencies":[]}),
    );
    let mut members = Vec::new();
    for (index, project) in projects.iter().enumerate() {
        let id = format!("project:{index}");
        let metadata = project.metadata();
        let project_name = metadata.name.unwrap_or_else(|| "project".into());
        let mut base = json!({"kind":"workspace","name":project_name,"version":metadata.version,"source":{"virtual":project.root()},"dependencies":links(&project.dependencies(),&packages)?});
        for (key, kind, groups) in [
            (
                "optional_dependencies",
                "extra",
                project.optional_dependencies(),
            ),
            ("dependency_groups", "group", project.dependency_groups()),
        ] {
            let mut choices = Vec::new();
            for (group, requirements) in groups {
                let child = format!("{id}:{kind}:{group}");
                let mut edges = links(&requirements, &packages)?;
                if kind == "extra" {
                    edges.push(json!({"id":id}));
                }
                let mut node_kind = Map::new();
                node_kind.insert(kind.into(), json!(group));
                resolution.insert(child.clone(),json!({"kind":node_kind,"name":project_name,"version":metadata.version,"source":{"virtual":project.root()},"dependencies":edges}));
                choices.push(json!({"name":group,"id":child}));
            }
            base[key] = json!(choices);
        }
        resolution.insert(id.clone(), base);
        members.push(json!({"id":id,"name":project_name}));
    }
    Ok(GraphEvidence {
        metadata: json!({"schema":{"version":"native"},"members":members,"workspace":{"id":"workspace"},"resolution":resolution}),
        backend: json!({"name":"native","version":env!("CARGO_PKG_VERSION"),"graph_source":"pybun.lockb+current_declarations"}),
        lock: json!({"source":path,"digest":hex::encode(Sha256::digest(&bytes))}),
        packages: inventory,
    })
}
