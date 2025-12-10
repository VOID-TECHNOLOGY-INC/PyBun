//! PEP 723 script metadata parser.
//!
//! Parses embedded metadata from Python scripts in the format:
//!
//! ```python
//! # /// script
//! # requires-python = ">=3.11"
//! # dependencies = [
//! #   "requests>=2.28.0",
//! #   "numpy",
//! # ]
//! # ///
//! ```

use serde::Deserialize;
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Pep723Error {
    #[error("failed to read script file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse script metadata: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("no script metadata block found")]
    NotFound,
}

pub type Result<T> = std::result::Result<T, Pep723Error>;

/// Script metadata extracted from PEP 723 block.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ScriptMetadata {
    /// Required Python version (e.g., ">=3.11")
    #[serde(default)]
    pub requires_python: Option<String>,
    /// List of dependencies (PEP 508 format)
    #[serde(default)]
    pub dependencies: Vec<String>,
}

/// Extract PEP 723 metadata from a Python script file.
pub fn parse_script_metadata(path: impl AsRef<Path>) -> Result<Option<ScriptMetadata>> {
    let content = fs::read_to_string(path)?;
    parse_script_metadata_from_str(&content)
}

/// Extract PEP 723 metadata from script content string.
pub fn parse_script_metadata_from_str(content: &str) -> Result<Option<ScriptMetadata>> {
    let toml_content = extract_metadata_block(content)?;
    match toml_content {
        Some(toml_str) => {
            let metadata: ScriptMetadata = toml::from_str(&toml_str)?;
            Ok(Some(metadata))
        }
        None => Ok(None),
    }
}

/// Extract the raw TOML content from the script block.
fn extract_metadata_block(content: &str) -> Result<Option<String>> {
    let start_marker = "# /// script";
    let end_marker = "# ///";

    let mut in_block = false;
    let mut toml_lines = Vec::new();
    let mut found = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if !in_block && trimmed == start_marker {
            in_block = true;
            found = true;
            continue;
        }

        if in_block {
            if trimmed == end_marker {
                break;
            }

            // Remove the leading "# " from the line
            let toml_line = if let Some(stripped) = trimmed.strip_prefix("# ") {
                stripped
            } else if let Some(stripped) = trimmed.strip_prefix("#") {
                stripped
            } else {
                // Line doesn't start with #, end the block
                break;
            };

            toml_lines.push(toml_line);
        }
    }

    if found && !toml_lines.is_empty() {
        Ok(Some(toml_lines.join("\n")))
    } else if found {
        // Empty block is valid
        Ok(Some(String::new()))
    } else {
        Ok(None)
    }
}

/// Check if a file has PEP 723 metadata without fully parsing it.
pub fn has_script_metadata(content: &str) -> bool {
    content.contains("# /// script")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_script_metadata() {
        let script = r#"#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "requests>=2.28.0",
#   "numpy",
# ]
# ///

import requests
print("hello")
"#;

        let metadata = parse_script_metadata_from_str(script)
            .unwrap()
            .expect("should have metadata");

        assert_eq!(metadata.requires_python, Some(">=3.11".to_string()));
        assert_eq!(metadata.dependencies.len(), 2);
        assert_eq!(metadata.dependencies[0], "requests>=2.28.0");
        assert_eq!(metadata.dependencies[1], "numpy");
    }

    #[test]
    fn parse_empty_dependencies() {
        let script = r#"# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
print("hello")
"#;

        let metadata = parse_script_metadata_from_str(script)
            .unwrap()
            .expect("should have metadata");

        assert_eq!(metadata.requires_python, Some(">=3.9".to_string()));
        assert!(metadata.dependencies.is_empty());
    }

    #[test]
    fn parse_no_metadata() {
        let script = r#"#!/usr/bin/env python3
print("hello")
"#;

        let result = parse_script_metadata_from_str(script).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_only_dependencies() {
        let script = r#"# /// script
# dependencies = ["click"]
# ///
import click
"#;

        let metadata = parse_script_metadata_from_str(script)
            .unwrap()
            .expect("should have metadata");

        assert!(metadata.requires_python.is_none());
        assert_eq!(metadata.dependencies, vec!["click"]);
    }

    #[test]
    fn has_script_metadata_returns_true() {
        let script = r#"# /// script
# dependencies = []
# ///"#;
        assert!(has_script_metadata(script));
    }

    #[test]
    fn has_script_metadata_returns_false() {
        let script = "print('hello')";
        assert!(!has_script_metadata(script));
    }

    #[test]
    fn parse_multiline_array() {
        let script = r#"# /// script
# dependencies = [
#     "requests>=2.28.0",
#     "rich",
#     "typer>=0.9.0",
# ]
# ///
"#;

        let metadata = parse_script_metadata_from_str(script)
            .unwrap()
            .expect("should have metadata");

        assert_eq!(metadata.dependencies.len(), 3);
        assert_eq!(metadata.dependencies[0], "requests>=2.28.0");
        assert_eq!(metadata.dependencies[1], "rich");
        assert_eq!(metadata.dependencies[2], "typer>=0.9.0");
    }

    #[test]
    fn parse_empty_block() {
        let script = r#"# /// script
# ///
print("no deps")
"#;

        let metadata = parse_script_metadata_from_str(script)
            .unwrap()
            .expect("should have metadata");

        assert!(metadata.requires_python.is_none());
        assert!(metadata.dependencies.is_empty());
    }

    #[test]
    fn ignores_content_after_block() {
        let script = r#"# /// script
# dependencies = ["numpy"]
# ///
# This is just a comment, not part of the block
# dependencies = ["should-not-parse"]
import numpy
"#;

        let metadata = parse_script_metadata_from_str(script)
            .unwrap()
            .expect("should have metadata");

        assert_eq!(metadata.dependencies, vec!["numpy"]);
    }
}
