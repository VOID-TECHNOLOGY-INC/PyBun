use crate::security_assessment::{
    InventoryBackend, InventoryScope, InventoryTarget, semantic_digest,
};
use serde::{Deserialize, Serialize};
use std::{fmt, path::PathBuf};

pub const MAX_MONITORS: usize = 100;
pub const MAX_INVENTORY: usize = 1000;
pub const MAX_EVENTS: usize = 1000;
pub const MAX_HISTORY_SECONDS: u64 = 90 * 86400;
pub const REPLAY_PAGE_SIZE: usize = 100;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CommitStatus {
    NotCommitted,
    Committed,
    Indeterminate,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MonitorError {
    pub code: String,
    pub commit_status: CommitStatus,
    pub message: String,
    pub replay: Option<Box<super::state::ReplayPage>>,
}
impl MonitorError {
    pub(crate) fn new(code: &str) -> Self {
        Self {replay:None,code:code.into(),commit_status:CommitStatus::NotCommitted,message:"Monitor state operation could not be completed; existing evidence must not be treated as rolled back or resolved.".into()}
    }
    pub(crate) fn indeterminate(mut self) -> Self {
        self.commit_status = CommitStatus::Indeterminate;
        self
    }
}
impl fmt::Display for MonitorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for MonitorError {}
pub type MonitorResult<T> = Result<T, MonitorError>;

#[derive(Debug, Clone)]
pub struct StoreOptions {
    pub root: PathBuf,
    pub allow_in_repository: bool,
    pub limits: MonitorLimits,
    pub deadline: Option<std::time::Instant>,
}
impl StoreOptions {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            allow_in_repository: false,
            limits: MonitorLimits::default(),
            deadline: None,
        }
    }
    pub fn user_default() -> MonitorResult<Self> {
        let root = dirs::state_dir()
            .or_else(dirs::data_local_dir)
            .ok_or_else(|| MonitorError::new("E_MONITOR_STATE_ROOT"))?
            .join("pybun/security-monitors");
        Ok(Self::new(root))
    }
}
#[derive(Debug, Clone)]
pub struct MonitorLimits {
    pub max_monitors: usize,
    pub max_inventory_instances: usize,
    pub retained_events: usize,
    pub history_seconds: u64,
    pub max_checkpoint_bytes: usize,
}
impl Default for MonitorLimits {
    fn default() -> Self {
        Self {
            max_monitors: MAX_MONITORS,
            max_inventory_instances: MAX_INVENTORY,
            retained_events: MAX_EVENTS,
            history_seconds: MAX_HISTORY_SECONDS,
            max_checkpoint_bytes: 64 * 1024 * 1024,
        }
    }
}
impl MonitorLimits {
    pub(crate) fn validate(&self) -> MonitorResult<()> {
        let cap = Self::default();
        if self.max_monitors == 0
            || self.max_monitors > cap.max_monitors
            || self.max_inventory_instances == 0
            || self.max_inventory_instances > cap.max_inventory_instances
            || self.retained_events == 0
            || self.retained_events > cap.retained_events
            || self.history_seconds == 0
            || self.history_seconds > cap.history_seconds
            || self.max_checkpoint_bytes == 0
            || self.max_checkpoint_bytes > cap.max_checkpoint_bytes
        {
            return Err(MonitorError::new("E_MONITOR_LIMIT"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeIdentity {
    pub interpreter_digest: String,
    pub tag_profile_digest: String,
    pub platform_identity_digest: String,
}
impl RuntimeIdentity {
    pub fn from_target(target: &crate::security_assessment::ObservedTarget) -> Self {
        Self {
            interpreter_digest: target.interpreter_digest.clone(),
            tag_profile_digest: semantic_digest(&target.tag_profile),
            platform_identity_digest: semantic_digest(&target.marker_environment),
        }
    }
}

/// Versionless comparison identity. Package versions, instance IDs, inventory
/// digests and ordinary project/lock contents deliberately do not belong here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ComparisonDomain {
    pub project_root: PathBuf,
    pub environment_root: PathBuf,
    pub backend: InventoryBackend,
    pub target: InventoryTarget,
    pub scope: InventoryScope,
    pub runtime: Option<RuntimeIdentity>,
    pub source_policy_digest: String,
    pub provider_config_digest: String,
    pub index_config_digest: String,
    pub observation_version: u32,
    pub authoritative_providers: Vec<String>,
}
impl ComparisonDomain {
    pub fn from_target(
        target: &crate::security_assessment::ObservedTarget,
        source_policy_digest: String,
        provider_config_digest: String,
        index_config_digest: String,
        authoritative_providers: Vec<String>,
        observation_version: u32,
    ) -> MonitorResult<Self> {
        let mut domain = Self {
            project_root: target.project_root.clone(),
            environment_root: target.environment_root.clone(),
            backend: target.backend,
            target: target.kind,
            scope: target.scope.clone(),
            runtime: Some(RuntimeIdentity::from_target(target)),
            source_policy_digest,
            provider_config_digest,
            index_config_digest,
            authoritative_providers,
            observation_version,
        };
        domain.validate()?;
        Ok(domain)
    }
    pub fn declared(&self) -> Self {
        let mut domain = self.clone();
        domain.runtime = None;
        domain
    }
    pub fn digest(&self) -> String {
        semantic_digest(self)
    }
    pub(crate) fn validate(&mut self) -> MonitorResult<()> {
        if !absolute_normal(&self.project_root)
            || !absolute_normal(&self.environment_root)
            || self.observation_version != 1
            || [
                &self.source_policy_digest,
                &self.provider_config_digest,
                &self.index_config_digest,
            ]
            .iter()
            .any(|value| !digest_valid(value))
        {
            return Err(MonitorError::new("E_MONITOR_CONFIG"));
        }
        if self.runtime.as_ref().is_some_and(|runtime| {
            [
                &runtime.interpreter_digest,
                &runtime.tag_profile_digest,
                &runtime.platform_identity_digest,
            ]
            .iter()
            .any(|digest| !digest_valid(digest))
        }) {
            return Err(MonitorError::new("E_MONITOR_CONFIG"));
        }
        if self.authoritative_providers.is_empty()
            || self.authoritative_providers.len() > 1000
            || self
                .authoritative_providers
                .iter()
                .any(|id| !crate::security_assessment::source::opaque_id(id))
        {
            return Err(MonitorError::new("E_MONITOR_CONFIG"));
        }
        self.authoritative_providers.sort();
        self.authoritative_providers.dedup();
        for values in [
            &mut self.scope.members,
            &mut self.scope.groups,
            &mut self.scope.extras,
        ] {
            if values.len() > 1000
                || values.iter().any(|value| {
                    value.is_empty() || value.len() > 200 || value.chars().any(char::is_control)
                })
            {
                return Err(MonitorError::new("E_MONITOR_CONFIG"));
            }
            values.sort();
            values.dedup();
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MonitorConfig {
    /// Stable operator configuration reference; never an authorization grant.
    pub profile_id: String,
    pub name: String,
    pub freshness_ttl_seconds: u64,
    #[serde(default)]
    pub include_prereleases: bool,
    pub domain: ComparisonDomain,
}
impl MonitorConfig {
    pub(crate) fn validate(&mut self) -> MonitorResult<()> {
        if !crate::security_assessment::source::opaque_id(&self.profile_id)
            || self.name.trim().is_empty()
            || self.name.len() > 200
            || self.name.chars().any(char::is_control)
            || self.freshness_ttl_seconds == 0
        {
            return Err(MonitorError::new("E_MONITOR_CONFIG"));
        }
        self.domain.validate()
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BaselineState {
    NotStarted,
    Started,
    Initialized,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub monitor_id: String,
    pub epoch_id: String,
    pub config_revision: u64,
    pub config: MonitorConfig,
    pub baseline_state: BaselineState,
    pub observed_runtime: Option<RuntimeIdentity>,
    pub reset_reason: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Registry {
    pub registry_id: String,
    pub monitors: Vec<Registration>,
}
impl Default for Registry {
    fn default() -> Self {
        Self {
            registry_id: random_id(),
            monitors: vec![],
        }
    }
}

pub(crate) fn random_id() -> String {
    uuid::Uuid::new_v4().to_string()
}
pub(crate) fn valid_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value)
        .is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == value)
}
pub(crate) fn digest_valid(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
pub(crate) fn absolute_normal(path: &std::path::Path) -> bool {
    path.is_absolute()
        && path.components().all(|part| {
            matches!(
                part,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

/// Only a trusted adapter handling an explicit current operator recovery grant
/// should construct this value. It is deliberately not serializable.
#[derive(Debug)]
pub struct RecoveryAuthorization {
    _private: (),
}
impl RecoveryAuthorization {
    pub fn explicit_operator_action() -> Self {
        Self { _private: () }
    }
}
