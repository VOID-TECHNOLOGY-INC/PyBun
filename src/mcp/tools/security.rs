//! Thin transport over the same authorized operation used by the CLI.
use crate::security_assessment::{
    check::{authorize_and_run, check_json},
    config::PreparedCheck,
};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) async fn call_security_check(prepared: PreparedCheck) -> Value {
    let observed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    check_json(&authorize_and_run(prepared, observed_at).await)
}
