//! `pybun_resolve` MCP tool implementation.
//!
//! Extracted from `mcp.rs` (Issue #344).

use serde_json::{Value, json};
use std::path::PathBuf;

pub(crate) async fn call_resolve(args: Value) -> Result<String, String> {
    use crate::index::load_index_from_path;
    use crate::resolver::{Requirement, ResolveOptions, resolve_with_options};

    let requirements: Vec<String> = args
        .get("requirements")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    if requirements.is_empty() {
        return Err("No requirements provided".to_string());
    }

    // Parse requirements
    let parsed_reqs: Vec<Requirement> = requirements
        .iter()
        .map(|s| s.parse().unwrap_or_else(|_| Requirement::any(s.trim())))
        .collect();

    // Opt-in to pre-release versions (mirrors the CLI `--pre` flag).
    let resolve_options = ResolveOptions {
        allow_prerelease: args.get("pre").and_then(|p| p.as_bool()).unwrap_or(false),
        python_version: crate::commands::resolve_target_python_version(),
    };

    // Try to load index from common locations
    let index_path = args
        .get("index")
        .and_then(|i| i.as_str())
        .map(PathBuf::from);

    // If index path provided, use it; otherwise try default locations
    let index_result: Result<_, String> = if let Some(path) = index_path {
        load_index_from_path(&path).map_err(|e| e.to_string())
    } else {
        // Try fixtures/index.json for testing, then fail gracefully
        let default_paths = vec![
            PathBuf::from("fixtures/index.json"),
            PathBuf::from("tests/fixtures/index.json"),
        ];
        let mut result: Result<_, String> = Err("No index file found".to_string());
        for path in default_paths {
            if path.exists() {
                result = load_index_from_path(&path).map_err(|e| e.to_string());
                if result.is_ok() {
                    break;
                }
            }
        }
        result
    };

    match index_result {
        Ok(index) => {
            match resolve_with_options(parsed_reqs.clone(), &index, resolve_options).await {
                Ok(resolution) => {
                    let packages: Vec<Value> = resolution
                    .packages
                    .values()
                    .map(|pkg| {
                        json!({
                            "name": pkg.name,
                            "version": pkg.version,
                            "dependencies": pkg.dependencies.iter().map(|d| d.to_string()).collect::<Vec<_>>(),
                        })
                    })
                    .collect();

                    let prerelease_fallbacks: Vec<Value> = resolution
                        .prerelease_fallbacks
                        .iter()
                        .map(|p| json!({ "name": p.name, "version": p.version }))
                        .collect();

                    Ok(json!({
                        "status": "resolved",
                        "requirements": requirements,
                        "packages": packages,
                        "count": resolution.packages.len(),
                        "prerelease_fallbacks": prerelease_fallbacks,
                    })
                    .to_string())
                }
                Err(e) => Err(format!("Resolution failed: {}", e)),
            }
        }
        Err(e) => {
            // Return a partial result indicating index is not available
            Ok(json!({
                "status": "no_index",
                "requirements": requirements,
                "message": format!("Could not load package index: {}. Provide 'index' path in arguments.", e),
                "parsed_requirements": parsed_reqs.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
            })
            .to_string())
        }
    }
}
