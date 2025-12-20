use crate::project::ProjectMetadata;
use crate::security::sha256_file;
use serde::Serialize;
use std::path::{Path, PathBuf};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum SbomError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialize(#[from] serde_json::Error),
}

#[derive(Debug, Serialize)]
struct Tool {
    vendor: String,
    name: String,
    version: String,
}

#[derive(Debug, Serialize)]
struct Property {
    name: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct HashEntry {
    #[serde(rename = "alg")]
    algorithm: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct Component {
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    name: String,
    #[serde(rename = "type")]
    type_field: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purl: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    hashes: Vec<HashEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    properties: Vec<Property>,
}

#[derive(Debug, Serialize)]
struct Metadata {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tools: Vec<Tool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    component: Option<Component>,
}

#[derive(Debug, Serialize)]
pub struct CycloneDxBom {
    #[serde(rename = "bomFormat")]
    bom_format: String,
    #[serde(rename = "specVersion")]
    spec_version: String,
    version: u32,
    #[serde(rename = "serialNumber")]
    serial_number: String,
    metadata: Metadata,
    components: Vec<Component>,
}

#[derive(Debug, Clone)]
pub struct SbomSummary {
    pub path: PathBuf,
    pub format: String,
    pub component_count: usize,
}

impl CycloneDxBom {
    pub fn new(project: &ProjectMetadata, artifacts: &[PathBuf]) -> Result<Self, SbomError> {
        let project_name = project
            .name
            .clone()
            .unwrap_or_else(|| "unknown-project".to_string());
        let project_version = project
            .version
            .clone()
            .unwrap_or_else(|| "0.0.0".to_string());
        let metadata_component = Component {
            bom_ref: project_name.clone(),
            name: project_name.clone(),
            type_field: "application".to_string(),
            version: Some(project_version.clone()),
            purl: Some(format!("pkg:generic/{project_name}@{project_version}")),
            hashes: vec![],
            properties: vec![],
        };

        let mut components = Vec::new();
        for artifact in artifacts {
            let name = artifact
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("artifact")
                .to_string();
            let hash = sha256_file(artifact)?;
            components.push(Component {
                bom_ref: format!("artifact:{name}"),
                name,
                type_field: "file".to_string(),
                version: project.version.clone(),
                purl: None,
                hashes: vec![HashEntry {
                    algorithm: "SHA-256".to_string(),
                    content: hash,
                }],
                properties: vec![Property {
                    name: "path".to_string(),
                    value: artifact.display().to_string(),
                }],
            });
        }

        Ok(Self {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.5".to_string(),
            version: 1,
            serial_number: format!("urn:uuid:{}", Uuid::new_v4()),
            metadata: Metadata {
                tools: vec![Tool {
                    vendor: "PyBun".to_string(),
                    name: "pybun".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                }],
                component: Some(metadata_component),
            },
            components,
        })
    }

    pub fn to_pretty_json(&self) -> Result<String, SbomError> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

/// Generate a CycloneDX SBOM and write it to the given path.
pub fn write_cyclonedx_sbom(
    output: &Path,
    project: &ProjectMetadata,
    artifacts: &[PathBuf],
) -> Result<SbomSummary, SbomError> {
    let bom = CycloneDxBom::new(project, artifacts)?;
    let json = bom.to_pretty_json()?;
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(output, json)?;
    Ok(SbomSummary {
        path: output.to_path_buf(),
        format: "CycloneDX".to_string(),
        component_count: bom.components.len(),
    })
}
