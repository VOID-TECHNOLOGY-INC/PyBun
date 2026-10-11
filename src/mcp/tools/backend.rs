//! Translate MCP arguments into the same typed CLI requests used by the adapter.
use clap::Parser;
use serde_json::Value;

pub(crate) async fn call_project(operation: &str, args: Value) -> Result<String, String> {
    if crate::backend::native_selected() {
        return Err("New project tools require the uv backend.".to_string());
    }
    let mut argv = vec!["pybun".to_string(), operation.to_string()];
    for key in ["offline", "pre", "workspace", "system", "dry_run"] {
        if let Some(value) = args.get(key) {
            let flag = value
                .as_bool()
                .ok_or_else(|| format!("{key} must be a boolean"))?;
            if flag {
                argv.push(format!("--{}", key.replace('_', "-")));
            }
        }
    }
    for key in ["member", "group", "index", "lock", "script"] {
        if let Some(value) = args.get(key) {
            argv.push(format!("--{key}"));
            argv.push(
                value
                    .as_str()
                    .ok_or_else(|| format!("{key} must be a string"))?
                    .to_string(),
            );
        }
    }
    for key in ["requirements", "packages"] {
        if let Some(values) = args.get(key) {
            for value in values
                .as_array()
                .ok_or_else(|| format!("{key} must be an array"))?
            {
                if key == "requirements" {
                    argv.push("--require".to_string());
                }
                argv.push(
                    value
                        .as_str()
                        .ok_or_else(|| format!("{key} items must be strings"))?
                        .to_string(),
                );
            }
        }
    }
    if let Some(package) = args.get("package") {
        let package = package.as_str().ok_or("package must be a string")?;
        let spec = match args.get("version") {
            Some(version) => format!(
                "{package}=={}",
                version.as_str().ok_or("version must be a string")?
            ),
            None => package.to_string(),
        };
        argv.push(spec);
    }
    // Never expose clap's input-echoing error text to callers or receipts.
    let cli = crate::cli::Cli::try_parse_from(argv)
        .map_err(|_| "Invalid project operation arguments".to_string())?;
    let request = crate::backend::BackendRequest::from_command(&cli.command)
        .map_err(|e| e.detail(operation).to_string())?;
    crate::backend::execute(request)
        .await
        .map(|v| v.to_string())
        .map_err(|e| e.detail(operation).to_string())
}
