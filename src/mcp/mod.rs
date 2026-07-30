//! MCP (Model Context Protocol) Server Implementation
//!
//! PR4.3: MCP server for programmatic control of PyBun.
//! PR4.3b: Implemented real tool execution (resolve, install, run, doctor).
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
//! - `pybun_doctor`: Run environment diagnostics
//!
//! Issue #344: split into `audit` (audit log + sandbox glue), `schema`
//! (tools/list definitions), and `tools` (per-tool handlers).

mod audit;
mod schema;
mod tools;

use audit::McpAuditLog;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use uuid::Uuid;

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
    session_id: String,
    audit_log: McpAuditLog,
}

impl McpServer {
    pub fn new() -> Self {
        Self {
            initialized: false,
            session_id: Uuid::new_v4().to_string(),
            audit_log: McpAuditLog::new(),
        }
    }

    /// Handle a JSON-RPC request
    pub async fn handle_request(&mut self, request: JsonRpcRequest) -> Option<JsonRpcResponse> {
        // Check for notifications that we explicitly handle
        match request.method.as_str() {
            "initialized" | "notifications/initialized" => {
                return None;
            }
            _ => {}
        }

        // For all other methods, if there is no ID, it is a notification and we must not respond
        let id = match request.id {
            Some(id) => id,
            None => return None,
        };

        match request.method.as_str() {
            "initialize" => Some(self.handle_initialize(id, request.params)),
            "tools/list" => Some(self.handle_tools_list(id)),
            "tools/call" => Some(self.handle_tools_call(id, request.params).await),
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
        JsonRpcResponse::success(id, json!({ "tools": schema::build_tools_list() }))
    }

    async fn handle_tools_call(&mut self, id: Value, params: Value) -> JsonRpcResponse {
        let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let tool_args = params.get("arguments").cloned().unwrap_or(json!({}));

        let start = Instant::now();
        let before_snapshot = audit::snapshot_for_tool(tool_name, &tool_args);
        let result = if let Err(err) = self.audit_log.prepare_for_call(&tool_args) {
            Err(err)
        } else {
            match tool_name {
                "pybun_resolve" => tools::call_resolve(tool_args.clone()).await,
                "pybun_install" => tools::call_install(tool_args.clone()).await,
                "pybun_run" => tools::call_run(tool_args.clone()).await,
                "pybun_gc" => tools::call_gc(tool_args.clone()),
                "pybun_doctor" => tools::call_doctor(tool_args.clone()),
                "pybun_lint" => tools::call_lint(tool_args.clone()),
                "pybun_type_check" => tools::call_type_check(tool_args.clone()),
                "pybun_profile" => tools::call_profile(tool_args.clone()),
                "pybun_fix" => tools::call_fix(tool_args.clone()),
                "pybun_context" => tools::call_context(tool_args.clone()),
                "pybun_drift" => tools::call_drift(tool_args.clone()),
                "pybun_test" => tools::call_test(tool_args.clone()),
                "pybun_audit" => tools::call_audit(tool_args.clone()).await,
                "pybun_upgrade" => tools::call_upgrade(tool_args.clone()),
                _ => Err(format!("Unknown tool: {}", tool_name)),
            }
        };
        let after_snapshot = audit::snapshot_for_tool(tool_name, &tool_args);
        let file_writes = audit::diff_file_writes(&before_snapshot, &after_snapshot);
        let duration_ms = start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;

        let audit_entry = audit::build_audit_entry(
            &self.session_id,
            tool_name,
            &tool_args,
            &result,
            self.audit_log.config.hash_inputs,
            file_writes,
            duration_ms,
        );
        self.audit_log.record(audit_entry);

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
            Resource {
                uri: "pybun://audit/recent".to_string(),
                name: "Recent MCP Audit Entries".to_string(),
                description: Some("Last 20 audited tool calls for this MCP session".to_string()),
                mime_type: Some("application/json".to_string()),
            },
            Resource {
                uri: "pybun://project/snapshot".to_string(),
                name: "Project State Snapshot".to_string(),
                description: Some("Single-call project state: Python version, venv, lockfile, installed packages, and doctor warnings".to_string()),
                mime_type: Some("application/json".to_string()),
            },
        ];

        JsonRpcResponse::success(id, json!({ "resources": resources }))
    }

    fn handle_resources_read(&self, id: Value, params: Value) -> JsonRpcResponse {
        let uri = params.get("uri").and_then(|u| u.as_str()).unwrap_or("");

        let content = match uri {
            "pybun://cache/info" => tools::read_cache_info(),
            "pybun://env/info" => tools::read_env_info(),
            "pybun://audit/recent" => Ok(self.read_audit_recent()),
            "pybun://project/snapshot" => tools::call_context(json!({})),
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

    fn read_audit_recent(&self) -> String {
        self.audit_log.recent_json(&self.session_id)
    }
}

impl Default for McpServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Run the MCP server in stdio mode
pub async fn run_stdio_server() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("PyBun MCP server starting (stdio mode)...");

    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    let mut server = McpServer::new();

    while let Ok(Some(line)) = lines.next_line().await {
        if line.trim().is_empty() {
            continue;
        }

        let request: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(req) => req,
            Err(e) => {
                eprintln!("Invalid JSON-RPC request: {}", e);
                let error_response = JsonRpcResponse::error(Value::Null, -32700, "Parse error");
                let _ = stdout
                    .write_all(serde_json::to_string(&error_response)?.as_bytes())
                    .await;
                let _ = stdout.write_all(b"\n").await;
                let _ = stdout.flush().await;
                continue;
            }
        };

        if let Some(response) = server.handle_request(request).await {
            let response_json = serde_json::to_string(&response)?;
            stdout.write_all(response_json.as_bytes()).await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }
    }

    eprintln!("PyBun MCP server stopped.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_initialize() {
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

        let response = server.handle_request(request).await.unwrap();
        assert!(response.result.is_some());
        let result = response.result.unwrap();
        assert!(result.get("protocolVersion").is_some());
        assert!(result.get("serverInfo").is_some());
    }

    #[tokio::test]
    async fn test_tools_list() {
        let mut server = McpServer::new();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "tools/list".to_string(),
            params: json!({}),
            id: Some(json!(2)),
        };

        let response = server.handle_request(request).await.unwrap();
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

    #[tokio::test]
    async fn test_resources_list() {
        let mut server = McpServer::new();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "resources/list".to_string(),
            params: json!({}),
            id: Some(json!(3)),
        };

        let response = server.handle_request(request).await.unwrap();
        assert!(response.result.is_some());
        let result = response.result.unwrap();
        let resources = result.get("resources").unwrap().as_array().unwrap();
        assert!(!resources.is_empty());
    }

    #[tokio::test]
    async fn test_unknown_method() {
        let mut server = McpServer::new();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "unknown/method".to_string(),
            params: json!({}),
            id: Some(json!(4)),
        };

        let response = server.handle_request(request).await.unwrap();
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32601);
    }

    #[tokio::test]
    async fn test_tools_call_gc() {
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

        let response = server.handle_request(request).await.unwrap();
        assert!(response.result.is_some());
    }

    #[tokio::test]
    async fn test_notification_handling() {
        let mut server = McpServer::new();

        // 1. "initialized" notification (standard) - should return None
        let req1 = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "initialized".to_string(),
            params: json!({}),
            id: None,
        };
        assert!(server.handle_request(req1).await.is_none());

        // 2. "notifications/initialized" (custom) - should return None
        let req2 = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "notifications/initialized".to_string(),
            params: json!({}),
            id: None,
        };
        assert!(server.handle_request(req2).await.is_none());

        // 3. "tools/list" as notification (missing id) - should return None (spec compliance)
        let req3 = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "tools/list".to_string(),
            params: json!({}),
            id: None,
        };
        assert!(server.handle_request(req3).await.is_none());

        // 4. "unknown/method" as notification (missing id) - should return None (no error)
        let req4 = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "unknown/method".to_string(),
            params: json!({}),
            id: None,
        };
        assert!(server.handle_request(req4).await.is_none());
    }
}
