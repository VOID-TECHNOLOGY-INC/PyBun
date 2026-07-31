//! Per-tool MCP handler implementations, grouped by concern.
//!
//! Extracted from `mcp.rs` (Issue #344).

mod install;
mod maintenance;
mod resolve;
mod run;

pub(crate) use install::call_install;
pub(crate) use maintenance::{
    call_audit, call_context, call_doctor, call_drift, call_fix, call_gc, call_lint, call_profile,
    call_test, call_type_check, call_upgrade, read_cache_info, read_env_info,
};
pub(crate) use resolve::call_resolve;
pub(crate) use run::call_run;
