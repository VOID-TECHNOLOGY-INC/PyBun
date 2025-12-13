//! JSON Event Schema Module (PR4.1)
//!
//! This module defines the global JSON schema for all CLI output,
//! ensuring consistent, machine-readable output for AI/MCP integration.
//!
//! ## Schema Version
//! Current schema version: 1
//!
//! ## Envelope Structure
//! All JSON responses follow this structure:
//! ```json
//! {
//!   "version": "1",
//!   "command": "pybun <command>",
//!   "status": "ok" | "error",
//!   "duration_ms": 123,
//!   "detail": { ... command-specific payload ... },
//!   "events": [ ... event stream ... ],
//!   "diagnostics": [ ... diagnostic messages ... ],
//!   "trace_id": "uuid" (optional, present when PYBUN_TRACE=1)
//! }
//! ```

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Schema version - bump when breaking changes occur
pub const SCHEMA_VERSION: &str = "1";

/// Response status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Error,
}

/// Diagnostic severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticLevel {
    Error,
    Warning,
    Info,
    Hint,
}

/// A diagnostic message with structured information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    /// Severity level
    pub level: DiagnosticLevel,
    /// Diagnostic code (e.g., "E001", "W002")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Human-readable message
    pub message: String,
    /// Related file path (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Line number (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// Suggested fix or action
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
    /// Additional context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
}

impl Diagnostic {
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            level: DiagnosticLevel::Error,
            code: None,
            message: message.into(),
            file: None,
            line: None,
            suggestion: None,
            context: None,
        }
    }

    pub fn warning(message: impl Into<String>) -> Self {
        Self {
            level: DiagnosticLevel::Warning,
            code: None,
            message: message.into(),
            file: None,
            line: None,
            suggestion: None,
            context: None,
        }
    }

    pub fn info(message: impl Into<String>) -> Self {
        Self {
            level: DiagnosticLevel::Info,
            code: None,
            message: message.into(),
            file: None,
            line: None,
            suggestion: None,
            context: None,
        }
    }

    pub fn hint(message: impl Into<String>) -> Self {
        Self {
            level: DiagnosticLevel::Hint,
            code: None,
            message: message.into(),
            file: None,
            line: None,
            suggestion: None,
            context: None,
        }
    }

    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(code.into());
        self
    }

    pub fn with_file(mut self, file: impl Into<String>) -> Self {
        self.file = Some(file.into());
        self
    }

    pub fn with_line(mut self, line: u32) -> Self {
        self.line = Some(line);
        self
    }

    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestion = Some(suggestion.into());
        self
    }

    pub fn with_context(mut self, context: Value) -> Self {
        self.context = Some(context);
        self
    }
}

/// Event type enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    // Lifecycle events
    CommandStart,
    CommandEnd,

    // Resolution events
    ResolveStart,
    ResolveProgress,
    ResolveComplete,

    // Installation events
    InstallStart,
    DownloadStart,
    DownloadProgress,
    DownloadComplete,
    ExtractStart,
    ExtractComplete,
    InstallComplete,

    // Runtime events
    EnvCreate,
    EnvActivate,
    ScriptStart,
    ScriptEnd,

    // Cache events
    CacheHit,
    CacheMiss,
    CacheWrite,

    // Python management events
    PythonListStart,
    PythonListComplete,
    PythonInstallStart,
    PythonInstallComplete,
    PythonRemoveStart,
    PythonRemoveComplete,

    // Module finder events
    ModuleFindStart,
    ModuleFindComplete,

    // Lazy import events
    LazyImportStart,
    LazyImportComplete,

    // Hot reload/watch events
    WatchStart,
    WatchStop,
    FileChange,

    // Generic progress event
    Progress,

    // Custom/extension event
    Custom,
}

/// An event in the command execution stream
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Event type
    #[serde(rename = "type")]
    pub event_type: EventType,
    /// Timestamp in milliseconds since command start
    pub timestamp_ms: u64,
    /// Event-specific data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    /// Progress percentage (0-100) if applicable
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<u8>,
    /// Human-readable message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Event {
    pub fn new(event_type: EventType, timestamp_ms: u64) -> Self {
        Self {
            event_type,
            timestamp_ms,
            data: None,
            progress: None,
            message: None,
        }
    }

    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    pub fn with_progress(mut self, progress: u8) -> Self {
        self.progress = Some(progress.min(100));
        self
    }

    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }
}

/// The JSON response envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonEnvelope {
    /// Schema version
    pub version: String,
    /// Command that was executed
    pub command: String,
    /// Execution status
    pub status: Status,
    /// Duration in milliseconds
    pub duration_ms: u64,
    /// Command-specific result data
    pub detail: Value,
    /// Event stream during execution
    pub events: Vec<Event>,
    /// Diagnostic messages
    pub diagnostics: Vec<Diagnostic>,
    /// Trace ID for distributed tracing (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
}

impl JsonEnvelope {
    pub fn new(
        command: impl Into<String>,
        status: Status,
        duration: Duration,
        detail: Value,
    ) -> Self {
        Self {
            version: SCHEMA_VERSION.to_string(),
            command: command.into(),
            status,
            duration_ms: duration.as_millis() as u64,
            detail,
            events: Vec::new(),
            diagnostics: Vec::new(),
            trace_id: None,
        }
    }

    pub fn ok(command: impl Into<String>, duration: Duration, detail: Value) -> Self {
        Self::new(command, Status::Ok, duration, detail)
    }

    pub fn error(command: impl Into<String>, duration: Duration, detail: Value) -> Self {
        Self::new(command, Status::Error, duration, detail)
    }

    pub fn with_events(mut self, events: Vec<Event>) -> Self {
        self.events = events;
        self
    }

    pub fn with_diagnostics(mut self, diagnostics: Vec<Diagnostic>) -> Self {
        self.diagnostics = diagnostics;
        self
    }

    pub fn with_trace_id(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }

    pub fn add_event(&mut self, event: Event) {
        self.events.push(event);
    }

    pub fn add_diagnostic(&mut self, diagnostic: Diagnostic) {
        self.diagnostics.push(diagnostic);
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("failed to serialize JSON envelope")
    }

    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).expect("failed to serialize JSON envelope")
    }
}

/// Event collector that tracks events during command execution
#[derive(Debug)]
pub struct EventCollector {
    start: Instant,
    events: Vec<Event>,
    diagnostics: Vec<Diagnostic>,
    trace_id: Option<String>,
}

impl EventCollector {
    pub fn new() -> Self {
        let trace_id = if std::env::var("PYBUN_TRACE").is_ok() {
            Some(Uuid::new_v4().to_string())
        } else {
            None
        };

        Self {
            start: Instant::now(),
            events: Vec::new(),
            diagnostics: Vec::new(),
            trace_id,
        }
    }

    pub fn with_trace_id(trace_id: impl Into<String>) -> Self {
        Self {
            start: Instant::now(),
            events: Vec::new(),
            diagnostics: Vec::new(),
            trace_id: Some(trace_id.into()),
        }
    }

    /// Record an event
    pub fn event(&mut self, event_type: EventType) -> &mut Event {
        let timestamp_ms = self.start.elapsed().as_millis() as u64;
        self.events.push(Event::new(event_type, timestamp_ms));
        self.events.last_mut().unwrap()
    }

    /// Record an event with data
    pub fn event_with_data(&mut self, event_type: EventType, data: Value) {
        let timestamp_ms = self.start.elapsed().as_millis() as u64;
        self.events
            .push(Event::new(event_type, timestamp_ms).with_data(data));
    }

    /// Record a diagnostic
    pub fn diagnostic(&mut self, diagnostic: Diagnostic) {
        self.diagnostics.push(diagnostic);
    }

    /// Record an error diagnostic
    pub fn error(&mut self, message: impl Into<String>) {
        self.diagnostics.push(Diagnostic::error(message));
    }

    /// Record a warning diagnostic
    pub fn warning(&mut self, message: impl Into<String>) {
        self.diagnostics.push(Diagnostic::warning(message));
    }

    /// Record an info diagnostic
    pub fn info(&mut self, message: impl Into<String>) {
        self.diagnostics.push(Diagnostic::info(message));
    }

    /// Get elapsed time since collector was created
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Get the trace ID if tracing is enabled
    pub fn trace_id(&self) -> Option<&str> {
        self.trace_id.as_deref()
    }

    /// Build the final envelope
    pub fn build_envelope(
        self,
        command: impl Into<String>,
        status: Status,
        detail: Value,
    ) -> JsonEnvelope {
        let duration = self.start.elapsed();
        let mut envelope = JsonEnvelope::new(command, status, duration, detail);
        envelope.events = self.events;
        envelope.diagnostics = self.diagnostics;
        envelope.trace_id = self.trace_id;
        envelope
    }

    /// Consume and get events
    pub fn into_events(self) -> Vec<Event> {
        self.events
    }

    /// Consume and get diagnostics
    pub fn into_diagnostics(self) -> Vec<Diagnostic> {
        self.diagnostics
    }

    /// Consume and get events, diagnostics, and trace_id together.
    ///
    /// This is convenient for command rendering where we need to include both
    /// streams in the final JSON envelope.
    pub fn into_parts(self) -> (Vec<Event>, Vec<Diagnostic>, Option<String>) {
        (self.events, self.diagnostics, self.trace_id)
    }
}

impl Default for EventCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_diagnostic_builder() {
        let diag = Diagnostic::error("something went wrong")
            .with_code("E001")
            .with_file("src/main.rs")
            .with_line(42)
            .with_suggestion("try this instead");

        assert_eq!(diag.level, DiagnosticLevel::Error);
        assert_eq!(diag.code, Some("E001".to_string()));
        assert_eq!(diag.message, "something went wrong");
        assert_eq!(diag.file, Some("src/main.rs".to_string()));
        assert_eq!(diag.line, Some(42));
        assert_eq!(diag.suggestion, Some("try this instead".to_string()));
    }

    #[test]
    fn test_event_builder() {
        let event = Event::new(EventType::InstallStart, 100)
            .with_message("installing package")
            .with_progress(50)
            .with_data(json!({"package": "requests"}));

        assert!(matches!(event.event_type, EventType::InstallStart));
        assert_eq!(event.timestamp_ms, 100);
        assert_eq!(event.message, Some("installing package".to_string()));
        assert_eq!(event.progress, Some(50));
    }

    #[test]
    fn test_envelope_serialization() {
        let envelope = JsonEnvelope::ok(
            "pybun install",
            Duration::from_millis(123),
            json!({"packages": ["requests"]}),
        )
        .with_events(vec![Event::new(EventType::CommandStart, 0)])
        .with_diagnostics(vec![Diagnostic::info("all good")]);

        let json = envelope.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["version"], "1");
        assert_eq!(parsed["command"], "pybun install");
        assert_eq!(parsed["status"], "ok");
        assert_eq!(parsed["duration_ms"], 123);
        assert!(parsed["events"].is_array());
        assert!(parsed["diagnostics"].is_array());
    }

    #[test]
    fn test_event_collector() {
        let mut collector = EventCollector::new();
        collector.event(EventType::CommandStart);
        collector.warning("something might be wrong");

        let envelope =
            collector.build_envelope("pybun test", Status::Ok, json!({"result": "passed"}));

        assert!(!envelope.events.is_empty());
        assert!(!envelope.diagnostics.is_empty());
    }

    #[test]
    fn test_trace_id_with_env() {
        // This test verifies trace ID behavior
        let collector = EventCollector::with_trace_id("test-trace-123");
        let envelope = collector.build_envelope("pybun test", Status::Ok, json!({}));
        assert_eq!(envelope.trace_id, Some("test-trace-123".to_string()));
    }

    #[test]
    fn test_status_serialization() {
        let ok = Status::Ok;
        let error = Status::Error;

        assert_eq!(serde_json::to_string(&ok).unwrap(), "\"ok\"");
        assert_eq!(serde_json::to_string(&error).unwrap(), "\"error\"");
    }

    #[test]
    fn test_diagnostic_level_serialization() {
        assert_eq!(
            serde_json::to_string(&DiagnosticLevel::Error).unwrap(),
            "\"error\""
        );
        assert_eq!(
            serde_json::to_string(&DiagnosticLevel::Warning).unwrap(),
            "\"warning\""
        );
        assert_eq!(
            serde_json::to_string(&DiagnosticLevel::Info).unwrap(),
            "\"info\""
        );
        assert_eq!(
            serde_json::to_string(&DiagnosticLevel::Hint).unwrap(),
            "\"hint\""
        );
    }
}
