//! Strict transport requests; persisted IDs and cursors confer no authority.
use super::diagnostic;
use crate::security_assessment::{
    ObservationDiagnostic, ObservationLimits,
    check::{CheckMode, CheckSeverityThreshold, CheckTarget},
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum MonitorRequest {
    List {
        #[serde(default)]
        profile: Option<String>,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    Add {
        name: String,
        #[serde(default)]
        profile: Option<String>,
        #[serde(default)]
        project: Option<PathBuf>,
        #[serde(default)]
        target: CheckTarget,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    Check {
        monitor_id: String,
        #[serde(default)]
        after: Option<String>,
        #[serde(default)]
        mode: CheckMode,
        #[serde(default)]
        fail_on: Option<CheckSeverityThreshold>,
        #[serde(default)]
        max_cache_age_seconds: Option<u64>,
        #[serde(default)]
        limits: Option<ObservationLimits>,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    Events {
        monitor_id: String,
        #[serde(default)]
        after: Option<String>,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    Configure {
        monitor_id: String,
        expected_revision: u64,
        profile: String,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    Remove {
        monitor_id: String,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
}
impl MonitorRequest {
    pub fn action(&self) -> &'static str {
        match self {
            Self::List { .. } => "list",
            Self::Add { .. } => "add",
            Self::Check { .. } => "check",
            Self::Events { .. } => "events",
            Self::Configure { .. } => "configure",
            Self::Remove { .. } => "remove",
        }
    }
    pub fn profile(&self) -> Option<&str> {
        match self {
            Self::List { profile, .. } | Self::Add { profile, .. } => profile.as_deref(),
            Self::Configure { profile, .. } => Some(profile),
            _ => None,
        }
    }
    pub fn writes(&self) -> bool {
        !matches!(self, Self::List { .. } | Self::Events { .. })
    }
    pub fn online(&self) -> bool {
        matches!(self,Self::Check{mode,..} if *mode!=CheckMode::Offline)
    }
    pub fn timeout_ms(&self) -> Option<u64> {
        match self {
            Self::List { timeout_ms, .. }
            | Self::Add { timeout_ms, .. }
            | Self::Check { timeout_ms, .. }
            | Self::Events { timeout_ms, .. }
            | Self::Configure { timeout_ms, .. }
            | Self::Remove { timeout_ms, .. } => *timeout_ms,
        }
    }
    pub(super) fn id(&self) -> Option<&str> {
        match self {
            Self::Check { monitor_id, .. }
            | Self::Events { monitor_id, .. }
            | Self::Configure { monitor_id, .. }
            | Self::Remove { monitor_id, .. } => Some(monitor_id),
            _ => None,
        }
    }
    pub(super) fn after(&self) -> Option<&str> {
        match self {
            Self::Check { after, .. } | Self::Events { after, .. } => after.as_deref(),
            _ => None,
        }
    }
    pub fn validate(&self) -> Result<(), ObservationDiagnostic> {
        if self
            .timeout_ms()
            .is_some_and(|value| value == 0 || value > 60_000)
            || self
                .id()
                .is_some_and(|id| !crate::security_assessment::source::opaque_id(id))
            || self
                .profile()
                .is_some_and(|id| !crate::security_assessment::source::opaque_id(id))
            || matches!(self,Self::Add{name,..} if name.trim().is_empty()||name.len()>200||name.chars().any(char::is_control))
            || matches!(
                self,
                Self::Configure {
                    expected_revision: 0,
                    ..
                }
            )
        {
            return Err(diagnostic("E_MONITOR_INPUT"));
        }
        if self.after().is_some_and(|after| after.len() > 2048) {
            return Err(diagnostic("E_MONITOR_INPUT"));
        }
        if let Self::Check {
            limits: Some(limits),
            ..
        } = self
        {
            limits.validate()?;
        }
        Ok(())
    }
}
