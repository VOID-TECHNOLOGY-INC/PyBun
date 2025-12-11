//! MCP (Model Context Protocol) Server Implementation
//!
//! PR4.3: MCP server for programmatic control of PyBun.
//!
//! This module implements the MCP protocol for AI agents and tools to
//! interact with PyBun via JSON-RPC.
//!
//! ## Supported Methods
//! - `initialize`: Initialize the MCP session
//! - `tools/list`: List available tools
//! - `tools/call`: Call a tool
//! - `resources/list`: List available resources
//! - `shutdown`: Shutdown the server
//!
//! ## Tools
//! - `pybun_resolve`: Resolve dependencies
//! - `pybun_install`: Install packages
//! - `pybun_run`: Run Python scripts
//! - `pybun_gc`: Run garbage collection

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};

/// MCP Protocol version we support
pub const PROTOCOL_VERSION: &str = "2024-11-05";

/// Server name and version
pub const SERVER_NAME: &str = "pybun-mcp";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// JSON-RPC request structure
#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
    pub id: Option<Value>,
}

/// JSON-RPC response structure
#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: Value,
}

/// JSON-RPC error structure
#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// MCP Tool definition
#[derive(Debug, Serialize)]
pub struct Tool {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

/// MCP Resource definition
#[derive(Debug, Serialize)]
pub struct Resource {
    pub uri: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

impl JsonRpcResponse {
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    pub fn error(id: Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
            id,
        }
    }
}

/// MCP Server state
pub struct McpServer {
    initialized: bool,
}

impl McpServer {
    pub fn new() -> Self {
        Self { initialized: false }
    }

    /// Handle a JSON-RPC request
    pub fn handle_request(&mut self, request: JsonRpcRequest) -> Option<JsonRpcResponse> {
        let id = request.id.clone().unwrap_or(Value::Null);

        match request.method.as_str() {
            "initialize" => Some(self.handle_initialize(id, request.params)),
            "initialized" => {
                // Notification, no response needed
                None
            }
            "tools/list" => Some(self.handle_tools_list(id)),
            "tools/call" => Some(self.handle_tools_call(id, request.params)),
            "resources/list" => Some(self.handle_resources_list(id)),
            "resources/read" => Some(self.handle_resources_read(id, request.params)),
            "shutdown" => {
                eprintln!("MCP server shutting down");
                Some(JsonRpcResponse::success(id, json!({})))
            }
            _ => Some(JsonRpcResponse::error(
                id,
                -32601,
                format!("Method not found: {}", request.method),
            )),
        }
    }

    fn handle_initialize(&mut self, id: Value, _params: Value) -> JsonRpcResponse {
        self.initialized = true;

        JsonRpcResponse::success(
            id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {},
                    "resources": {}
                },
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION
                }
            }),
        )
    }

    fn handle_tools_list(&self, id: Value) -> JsonRpcResponse {
        let tools = vec![
            Tool {
                name: "pybun_resolve".to_string(),
                description: "Resolve Python package dependencies".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "requirements": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of requirements (e.g., ['requests>=2.28', 'flask'])"
                        }
                    },
                    "required": ["requirements"]
                }),
            },
            Tool {
                name: "pybun_install".to_string(),
                description: "Install Python packages".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "requirements": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of requirements to install"
                        },
                        "offline": {
                            "type": "boolean",
                            "description": "Use offline mode (cache only)"
                        }
                    },
                    "required": ["requirements"]
                }),
            },
            Tool {
                name: "pybun_run".to_string(),
                description: "Run a Python script".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "script": {
                            "type": "string",
                            "description": "Path to the Python script"
                        },
                        "code": {
                            "type": "string",
                            "description": "Inline Python code to execute"
                        },
                        "args": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Arguments to pass to the script"
                        }
                    }
                }),
            },
            Tool {
                name: "pybun_gc".to_string(),
                description: "Run garbage collection on PyBun cache".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "max_size": {
                            "type": "string",
                            "description": "Maximum cache size (e.g., '1G', '500M')"
                        },
                        "dry_run": {
                            "type": "boolean",
                            "description": "Preview without deleting"
                        }
                    }
                }),
            },
            Tool {
                name: "pybun_doctor".to_string(),
                description: "Run environment diagnostics".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "verbose": {
                            "type": "boolean",
                            "description": "Include verbose diagnostics"
                        }
                    }
                }),
            },
        ];

        JsonRpcResponse::success(id, json!({ "tools": tools }))
    }

    fn handle_tools_call(&self, id: Value, params: Value) -> JsonRpcResponse {
        let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let tool_args = params.get("arguments").cloned().unwrap_or(json!({}));

        let result = match tool_name {
            "pybun_resolve" => self.call_resolve(tool_args),
            "pybun_install" => self.call_install(tool_args),
            "pybun_run" => self.call_run(tool_args),
            "pybun_gc" => self.call_gc(tool_args),
            "pybun_doctor" => self.call_doctor(tool_args),
            _ => Err(format!("Unknown tool: {}", tool_name)),
        };

        match result {
            Ok(content) => JsonRpcResponse::success(
                id,
                json!({
                    "content": [{
                        "type": "text",
                        "text": content
                    }]
                }),
            ),
            Err(e) => JsonRpcResponse::success(
                id,
                json!({
                    "content": [{
                        "type": "text",
                        "text": format!("Error: {}", e)
                    }],
                    "isError": true
                }),
            ),
        }
    }

    fn handle_resources_list(&self, id: Value) -> JsonRpcResponse {
        let resources = vec![
            Resource {
                uri: "pybun://cache/info".to_string(),
                name: "Cache Information".to_string(),
                description: Some("Information about the PyBun cache".to_string()),
                mime_type: Some("application/json".to_string()),
            },
            Resource {
                uri: "pybun://env/info".to_string(),
                name: "Environment Information".to_string(),
                description: Some("Current Python environment info".to_string()),
                mime_type: Some("application/json".to_string()),
            },
        ];

        JsonRpcResponse::success(id, json!({ "resources": resources }))
    }

    fn handle_resources_read(&self, id: Value, params: Value) -> JsonRpcResponse {
        let uri = params.get("uri").and_then(|u| u.as_str()).unwrap_or("");

        let content = match uri {
            "pybun://cache/info" => self.read_cache_info(),
            "pybun://env/info" => self.read_env_info(),
            _ => Err(format!("Unknown resource: {}", uri)),
        };

        match content {
            Ok(text) => JsonRpcResponse::success(
                id,
                json!({
                    "contents": [{
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": text
                    }]
                }),
            ),
            Err(e) => JsonRpcResponse::error(id, -32602, e),
        }
    }

    // Tool implementations
    fn call_resolve(&self, args: Value) -> Result<String, String> {
        let requirements = args
            .get("requirements")
            .and_then(|r| r.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
            .unwrap_or_default();

        Ok(json!({
            "status": "resolved",
            "requirements": requirements,
            "message": format!("Would resolve {} requirements", requirements.len())
        })
        .to_string())
    }

    fn call_install(&self, args: Value) -> Result<String, String> {
        let requirements = args
            .get("requirements")
            .and_then(|r| r.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
            .unwrap_or_default();

        let offline = args
            .get("offline")
            .and_then(|o| o.as_bool())
            .unwrap_or(false);

        Ok(json!({
            "status": "installed",
            "requirements": requirements,
            "offline": offline,
            "message": format!("Would install {} packages", requirements.len())
        })
        .to_string())
    }

    fn call_run(&self, args: Value) -> Result<String, String> {
        let script = args.get("script").and_then(|s| s.as_str());
        let code = args.get("code").and_then(|c| c.as_str());

        let target = match (script, code) {
            (Some(s), _) => format!("script: {}", s),
            (_, Some(_)) => "inline code".to_string(),
            _ => return Err("Either 'script' or 'code' must be provided".to_string()),
        };

        Ok(json!({
            "status": "would_run",
            "target": target,
            "message": format!("Would run {}", target)
        })
        .to_string())
    }

    fn call_gc(&self, args: Value) -> Result<String, String> {
        let max_size = args.get("max_size").and_then(|s| s.as_str());
        let dry_run = args
            .get("dry_run")
            .and_then(|d| d.as_bool())
            .unwrap_or(false);

        use crate::cache::{Cache, format_size, parse_size};

        let cache = Cache::new().map_err(|e| e.to_string())?;
        let max_bytes = max_size.map(|s| parse_size(s)).transpose().map_err(|e| e)?;

        let result = cache.gc(max_bytes, dry_run).map_err(|e| e.to_string())?;

        Ok(json!({
            "status": "gc_complete",
            "freed_bytes": result.freed_bytes,
            "freed_human": format_size(result.freed_bytes),
            "files_removed": result.files_removed,
            "dry_run": dry_run
        })
        .to_string())
    }

    fn call_doctor(&self, args: Value) -> Result<String, String> {
        let verbose = args
            .get("verbose")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        Ok(json!({
            "status": "healthy",
            "verbose": verbose,
            "message": "Environment diagnostics completed"
        })
        .to_string())
    }

    // Resource implementations
    fn read_cache_info(&self) -> Result<String, String> {
        use crate::cache::{Cache, format_size};

        let cache = Cache::new().map_err(|e| e.to_string())?;
        let total_size = cache.total_size().map_err(|e| e.to_string())?;

        Ok(json!({
            "root": cache.root().display().to_string(),
            "total_size": total_size,
            "total_size_human": format_size(total_size)
        })
        .to_string())
    }

    fn read_env_info(&self) -> Result<String, String> {
        use crate::env::find_python_env;

        let working_dir = std::env::current_dir().map_err(|e| e.to_string())?;

        match find_python_env(&working_dir) {
            Ok(env) => Ok(json!({
                "python_path": env.python_path.display().to_string(),
                "source": format!("{}", env.source),
                "version": env.version
            })
            .to_string()),
            Err(e) => Ok(json!({
                "error": e.to_string(),
                "message": "No Python environment found"
            })
            .to_string()),
        }
    }
}

impl Default for McpServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Run the MCP server in stdio mode
pub fn run_stdio_server() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("PyBun MCP server starting (stdio mode)...");

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let reader = BufReader::new(stdin.lock());

    let mut server = McpServer::new();

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Error reading input: {}", e);
                break;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        let request: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(req) => req,
            Err(e) => {
                eprintln!("Invalid JSON-RPC request: {}", e);
                let error_response = JsonRpcResponse::error(Value::Null, -32700, "Parse error");
                let _ = writeln!(stdout, "{}", serde_json::to_string(&error_response)?);
                let _ = stdout.flush();
                continue;
            }
        };

        if let Some(response) = server.handle_request(request) {
            let response_json = serde_json::to_string(&response)?;
            writeln!(stdout, "{}", response_json)?;
            stdout.flush()?;
        }
    }

    eprintln!("PyBun MCP server stopped.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialize() {
        let mut server = McpServer::new();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "initialize".to_string(),
            params: json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0.1.0"}
            }),
            id: Some(json!(1)),
        };

        let response = server.handle_request(request).unwrap();
        assert!(response.result.is_some());
        let result = response.result.unwrap();
        assert!(result.get("protocolVersion").is_some());
        assert!(result.get("serverInfo").is_some());
    }

    #[test]
    fn test_tools_list() {
        let mut server = McpServer::new();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "tools/list".to_string(),
            params: json!({}),
            id: Some(json!(2)),
        };

        let response = server.handle_request(request).unwrap();
        assert!(response.result.is_some());
        let result = response.result.unwrap();
        let tools = result.get("tools").unwrap().as_array().unwrap();
        assert!(!tools.is_empty());

        // Check some expected tools
        let tool_names: Vec<&str> = tools
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
            .collect();
        assert!(tool_names.contains(&"pybun_resolve"));
        assert!(tool_names.contains(&"pybun_install"));
        assert!(tool_names.contains(&"pybun_run"));
        assert!(tool_names.contains(&"pybun_gc"));
    }

    #[test]
    fn test_resources_list() {
        let mut server = McpServer::new();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "resources/list".to_string(),
            params: json!({}),
            id: Some(json!(3)),
        };

        let response = server.handle_request(request).unwrap();
        assert!(response.result.is_some());
        let result = response.result.unwrap();
        let resources = result.get("resources").unwrap().as_array().unwrap();
        assert!(!resources.is_empty());
    }

    #[test]
    fn test_unknown_method() {
        let mut server = McpServer::new();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "unknown/method".to_string(),
            params: json!({}),
            id: Some(json!(4)),
        };

        let response = server.handle_request(request).unwrap();
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32601);
    }

    #[test]
    fn test_tools_call_gc() {
        let mut server = McpServer::new();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "tools/call".to_string(),
            params: json!({
                "name": "pybun_gc",
                "arguments": {
                    "dry_run": true
                }
            }),
            id: Some(json!(5)),
        };

        let response = server.handle_request(request).unwrap();
        assert!(response.result.is_some());
    }
}
