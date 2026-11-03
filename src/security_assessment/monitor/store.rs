use super::{
    fs::{CommitObserver, CommitTarget, NoObserver, Root},
    model::*,
};
use std::sync::Arc;

/// Process-serialized private monitor state. Opening is read-only; creation and
/// registration require the adapter's current explicit state-write authority.
pub struct MonitorStore {
    pub(crate) root: Root,
    pub(crate) options: StoreOptions,
    pub(crate) observer: Arc<dyn CommitObserver>,
}
impl MonitorStore {
    /// Clone the actually opened directory, even if its pathname was replaced.
    /// The caller must independently validate that identity against its grant.
    pub fn root_handle(&self) -> std::io::Result<std::fs::File> {
        self.root.clone_handle()
    }

    pub fn create(options: StoreOptions) -> MonitorResult<Self> {
        Self::open_inner(options, true)
    }
    pub fn open(options: StoreOptions) -> MonitorResult<Self> {
        Self::open_inner(options, false)
    }
    fn open_inner(options: StoreOptions, create: bool) -> MonitorResult<Self> {
        let root = Root::open(&options, create)?;
        Ok(Self {
            root,
            options,
            observer: Arc::new(NoObserver),
        })
    }
    pub(crate) fn deadline(&self) -> std::time::Instant {
        self.options
            .deadline
            .unwrap_or_else(|| std::time::Instant::now() + std::time::Duration::from_secs(60))
    }
    pub fn with_observer(mut self, observer: Arc<dyn CommitObserver>) -> Self {
        self.observer = observer;
        self
    }
    pub(crate) fn registry(&self, lock: &super::fs::Lock) -> MonitorResult<Option<Registry>> {
        let registry: Option<Registry> = self.root.read("registry.json", 1024 * 1024, lock)?;
        if let Some(registry) = &registry {
            if !valid_id(&registry.registry_id) || registry.monitors.len() > MAX_MONITORS {
                return Err(MonitorError::new("E_MONITOR_STATE_CORRUPT"));
            }
            let mut ids = std::collections::BTreeSet::new();
            for entry in &registry.monitors {
                let mut config = entry.config.clone();
                config.validate()?;
                if !valid_id(&entry.monitor_id)
                    || !valid_id(&entry.epoch_id)
                    || entry.config_revision == 0
                    || !ids.insert(&entry.monitor_id)
                    || config != entry.config
                {
                    return Err(MonitorError::new("E_MONITOR_STATE_CORRUPT"));
                }
            }
        }
        Ok(registry)
    }
    fn required_registry(&self, lock: &super::fs::Lock) -> MonitorResult<Registry> {
        match self.registry(lock)? {
            Some(registry) => Ok(registry),
            None => Err(MonitorError::new(if self.root.has_checkpoints(lock)? {
                "E_MONITOR_REGISTRY_MISSING"
            } else {
                "E_MONITOR_NOT_FOUND"
            })),
        }
    }
    pub(crate) fn write_registry(
        &self,
        registry: &Registry,
        lock: &super::fs::Lock,
    ) -> MonitorResult<()> {
        self.root.write(
            "registry.json",
            registry,
            CommitTarget::Registry,
            1024 * 1024,
            &self.observer,
            lock,
        )
    }
    pub fn register(&self, mut config: MonitorConfig) -> MonitorResult<Registration> {
        config.validate()?;
        config.domain = config.domain.declared();
        let _lock = self.root.lock(self.deadline())?;
        let mut registry = self.registry(&_lock)?.unwrap_or_default();
        if registry.monitors.len() >= self.options.limits.max_monitors {
            return Err(MonitorError::new("E_MONITOR_LIMIT"));
        }
        let entry = Registration {
            monitor_id: random_id(),
            epoch_id: random_id(),
            config_revision: 1,
            config,
            baseline_state: BaselineState::NotStarted,
            observed_runtime: None,
            reset_reason: None,
        };
        registry.monitors.push(entry.clone());
        self.write_registry(&registry, &_lock)?;
        Ok(entry)
    }
    pub fn list(&self) -> MonitorResult<Vec<Registration>> {
        let _lock = self.root.lock(self.deadline())?;
        match self.registry(&_lock)? {
            Some(registry) => Ok(registry.monitors),
            None if self.root.has_checkpoints(&_lock)? => {
                Err(MonitorError::new("E_MONITOR_REGISTRY_MISSING"))
            }
            None => Ok(vec![]),
        }
    }
    pub fn remove(&self, id: &str) -> MonitorResult<bool> {
        if !valid_id(id) {
            return Err(MonitorError::new("E_MONITOR_ID"));
        }
        let _lock = self.root.lock(self.deadline())?;
        let Some(mut registry) = self.registry(&_lock)? else {
            return Ok(false);
        };
        let old = registry.monitors.len();
        registry.monitors.retain(|entry| entry.monitor_id != id);
        if old == registry.monitors.len() {
            return Ok(false);
        }
        self.write_registry(&registry, &_lock)?;
        Ok(true)
    }
}

impl MonitorStore {
    fn snapshot_name(id: &str) -> String {
        format!("{id}.checkpoint.json")
    }
    fn snapshot(
        &self,
        id: &str,
        lock: &super::fs::Lock,
    ) -> MonitorResult<Option<super::state::Snapshot>> {
        let snapshot: Option<super::state::Snapshot> = self.root.read(
            &Self::snapshot_name(id),
            self.options.limits.max_checkpoint_bytes,
            lock,
        )?;
        if let Some(value) = &snapshot {
            if value.monitor_id != id
                || !valid_id(&value.epoch_id)
                || value.config_revision == 0
                || value.generation == 0
                || value.events.len() > MAX_EVENTS
                || value
                    .events
                    .windows(2)
                    .any(|pair| pair[0].sequence >= pair[1].sequence)
                || value.events.iter().any(|event| {
                    event.monitor_id != id
                        || !valid_id(&event.epoch_id)
                        || event.sequence == 0
                        || event.sequence > value.sequence
                })
                || value
                    .lineages
                    .iter()
                    .any(|lineage| !valid_id(&lineage.finding.finding_id))
            {
                return Err(MonitorError::new("E_MONITOR_STATE_CORRUPT"));
            }
            if let Some(cursor) = &value.continuation {
                crate::security_assessment::qualification::schedule::AssessmentContinuation::parse(
                    cursor,
                )
                .map_err(|_| MonitorError::new("E_MONITOR_STATE_CORRUPT"))?;
            }
        }
        Ok(snapshot)
    }
    pub fn configure(
        &self,
        id: &str,
        expected_revision: u64,
        mut config: MonitorConfig,
    ) -> MonitorResult<Registration> {
        config.validate()?;
        config.domain = config.domain.declared();
        let lock = self.root.lock(self.deadline())?;
        let mut registry = self.required_registry(&lock)?;
        let registration = registry
            .monitors
            .iter_mut()
            .find(|entry| entry.monitor_id == id)
            .ok_or_else(|| MonitorError::new("E_MONITOR_NOT_FOUND"))?;
        if registration.config_revision != expected_revision {
            return Err(MonitorError::new("E_MONITOR_STALE_CONFIG"));
        }
        registration.config = config;
        registration.epoch_id = random_id();
        registration.config_revision = registration
            .config_revision
            .checked_add(1)
            .ok_or_else(|| MonitorError::new("E_MONITOR_LIMIT"))?;
        registration.baseline_state = BaselineState::NotStarted;
        registration.observed_runtime = None;
        registration.reset_reason = Some("configuration_changed".into());
        let result = registration.clone();
        self.write_registry(&registry, &lock)?;
        Ok(result)
    }
    pub fn recover_corrupt_snapshot(
        &self,
        id: &str,
        expected_revision: u64,
        _authorization: RecoveryAuthorization,
    ) -> MonitorResult<Registration> {
        if !valid_id(id) {
            return Err(MonitorError::new("E_MONITOR_ID"));
        }
        let lock = self.root.lock(self.deadline())?;
        let mut registry = self.required_registry(&lock)?;
        let entry = registry
            .monitors
            .iter_mut()
            .find(|entry| entry.monitor_id == id)
            .ok_or_else(|| MonitorError::new("E_MONITOR_NOT_FOUND"))?;
        if entry.config_revision != expected_revision {
            return Err(MonitorError::new("E_MONITOR_STALE_CONFIG"));
        }
        match self.snapshot(id, &lock) {
            Err(error) if error.code == "E_MONITOR_STATE_CORRUPT" => {}
            Err(error) => return Err(error),
            Ok(_) => return Err(MonitorError::new("E_MONITOR_RECOVERY_NOT_REQUIRED")),
        }
        self.root.quarantine(&Self::snapshot_name(id), &lock)?;
        entry.epoch_id = random_id();
        entry.config_revision = entry
            .config_revision
            .checked_add(1)
            .ok_or_else(|| MonitorError::new("E_MONITOR_LIMIT").indeterminate())?;
        entry.baseline_state = BaselineState::NotStarted;
        entry.observed_runtime = None;
        entry.reset_reason = Some("corrupt_observation_recovered".into());
        let result = entry.clone();
        self.write_registry(&registry, &lock)
            .map_err(MonitorError::indeterminate)?;
        Ok(result)
    }
    pub fn recover_corrupt_registry(
        &self,
        _authorization: RecoveryAuthorization,
    ) -> MonitorResult<()> {
        let lock = self.root.lock(self.deadline())?;
        match self.registry(&lock) {
            Err(error) if error.code == "E_MONITOR_STATE_CORRUPT" => {}
            Err(error) => return Err(error),
            Ok(_) => return Err(MonitorError::new("E_MONITOR_RECOVERY_NOT_REQUIRED")),
        }
        self.root.quarantine("registry.json", &lock)?;
        self.write_registry(
            &Registry {
                registry_id: random_id(),
                monitors: vec![],
            },
            &lock,
        )
        .map_err(MonitorError::indeterminate)
    }
    pub fn prepare_check(&self, id: &str) -> MonitorResult<super::state::PreparedCheck> {
        if !valid_id(id) {
            return Err(MonitorError::new("E_MONITOR_ID"));
        }
        let lock = self.root.lock(self.deadline())?;
        let mut registry = self.required_registry(&lock)?;
        let index = registry
            .monitors
            .iter()
            .position(|entry| entry.monitor_id == id)
            .ok_or_else(|| MonitorError::new("E_MONITOR_NOT_FOUND"))?;
        let previous = self.snapshot(id, &lock)?;
        if previous.is_none()
            && registry.monitors[index].baseline_state != BaselineState::NotStarted
        {
            let entry = &mut registry.monitors[index];
            let reason = if entry.baseline_state == BaselineState::Started {
                "initial_check_interrupted"
            } else {
                "observation_missing"
            };
            entry.epoch_id = random_id();
            entry.config_revision = entry
                .config_revision
                .checked_add(1)
                .ok_or_else(|| MonitorError::new("E_MONITOR_LIMIT"))?;
            entry.baseline_state = BaselineState::NotStarted;
            entry.observed_runtime = None;
            entry.reset_reason = Some(reason.into());
            self.write_registry(&registry, &lock)?;
        } else if previous
            .as_ref()
            .is_some_and(|snapshot| snapshot.epoch_id == registry.monitors[index].epoch_id)
            && registry.monitors[index].baseline_state == BaselineState::Started
        {
            registry.monitors[index].baseline_state = BaselineState::Initialized;
            self.write_registry(&registry, &lock)
                .map_err(MonitorError::indeterminate)?;
        }
        let same_epoch = previous
            .as_ref()
            .filter(|snapshot| snapshot.epoch_id == registry.monitors[index].epoch_id);
        let prior_candidates = same_epoch
            .into_iter()
            .flat_map(|snapshot| &snapshot.lineages)
            .filter_map(|lineage| {
                lineage.finding.candidate.as_ref().map(|candidate| {
                    (
                        lineage.finding.package_key.clone(),
                        candidate.version.clone(),
                    )
                })
            })
            .collect();
        Ok(super::state::PreparedCheck {
            registration: registry.monitors[index].clone(),
            generation: previous.as_ref().map_or(0, |snapshot| snapshot.generation),
            check_id: random_id(),
            prior_candidates,
            known_advisories: same_epoch
                .into_iter()
                .flat_map(|snapshot| &snapshot.lineages)
                .flat_map(|lineage| {
                    lineage.finding.evidence.iter().map(|evidence| {
                        super::state::KnownAdvisoryWitness {
                            package_key: lineage.finding.package_key.clone(),
                            provider_id: evidence.provider_id.clone(),
                            record_id: evidence.record_id.clone(),
                        }
                    })
                })
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect(),
            continuation: same_epoch.and_then(|snapshot| snapshot.continuation.clone()),
        })
    }
    pub fn events(
        &self,
        id: &str,
        after: Option<&super::state::EventReplayCursor>,
    ) -> MonitorResult<super::state::ReplayPage> {
        if !valid_id(id) {
            return Err(MonitorError::new("E_MONITOR_ID"));
        }
        let lock = self.root.lock(self.deadline())?;
        let registry = self.required_registry(&lock)?;
        let registration = registry
            .monitors
            .iter()
            .find(|entry| entry.monitor_id == id)
            .ok_or_else(|| MonitorError::new("E_MONITOR_NOT_FOUND"))?;
        let snapshot = self.snapshot(id, &lock)?;
        let Some(snapshot) = snapshot.filter(|snapshot| snapshot.epoch_id == registration.epoch_id)
        else {
            return Err(super::replay::pending(registration, after));
        };
        super::replay::page(&snapshot, after)
    }
    pub fn commit_check(
        &self,
        ticket: &super::state::PreparedCheck,
        assessment: &crate::security_assessment::qualification::service::SecurityAssessment,
        mut context: super::state::CheckContext,
        after: Option<&super::state::EventReplayCursor>,
    ) -> MonitorResult<super::state::CheckResult> {
        context.deadline = context.deadline.min(self.deadline());
        if std::time::Instant::now() >= context.deadline {
            return Err(MonitorError::new("E_MONITOR_DEADLINE"));
        }
        context.domain.validate()?;
        context.domain.runtime = if super::projection::fresh(
            context.inventory_freshness,
            assessment.inventory.observed_at,
            context.now,
            ticket.registration.config.freshness_ttl_seconds,
        ) {
            assessment
                .inventory
                .target
                .as_ref()
                .map(RuntimeIdentity::from_target)
        } else {
            None
        };
        let projection = super::projection::project(
            assessment,
            &ticket.registration.config,
            &context,
            &self.options.limits,
        )?;
        self.commit_projected(ticket, &projection, context, after)
    }
    pub fn commit_failure(
        &self,
        ticket: &super::state::PreparedCheck,
        diagnostics: &[super::state::MonitorDiagnostic],
        mut context: super::state::CheckContext,
        after: Option<&super::state::EventReplayCursor>,
    ) -> MonitorResult<super::state::CheckResult> {
        if diagnostics.is_empty()
            || diagnostics.len() > 100
            || diagnostics.iter().any(|item| {
                !item.code.starts_with("E_")
                    || item.code.len() > 128
                    || !item.code.bytes().all(|byte| {
                        byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
                    })
                    || !crate::security_assessment::source::opaque_id(&item.scope)
            })
        {
            return Err(MonitorError::new("E_MONITOR_INPUT"));
        }
        context.domain.validate()?;
        context.deadline = context.deadline.min(self.deadline());
        context.domain.runtime = ticket.registration.observed_runtime.clone();
        let projection = super::projection::Projected {
            packages: Default::default(),
            inventory_complete: false,
            online: context.mode == super::state::ObservationMode::Online,
            baseline_possible: false,
            complete: false,
            failures: diagnostics
                .iter()
                .map(|item| {
                    crate::security_assessment::semantic_digest(&(
                        &item.scope,
                        &item.code,
                        "assessment",
                    ))
                })
                .collect(),
            diagnostics: diagnostics.to_vec(),
            continuation: None,
        };
        self.commit_projected(ticket, &projection, context, after)
    }
    fn commit_projected(
        &self,
        ticket: &super::state::PreparedCheck,
        projection: &super::projection::Projected<'_>,
        context: super::state::CheckContext,
        after: Option<&super::state::EventReplayCursor>,
    ) -> MonitorResult<super::state::CheckResult> {
        use super::fs::CommitStage;
        let lock = self.root.lock(context.deadline)?;
        let mut registry = self.required_registry(&lock)?;
        let index = registry
            .monitors
            .iter()
            .position(|entry| entry.monitor_id == ticket.registration.monitor_id)
            .ok_or_else(|| MonitorError::new("E_MONITOR_NOT_FOUND"))?;
        let previous = self.snapshot(&ticket.registration.monitor_id, &lock)?;
        if let Some(snapshot) = previous.as_ref().filter(|snapshot| {
            snapshot.last_check.check_id == ticket.check_id
                && snapshot.epoch_id == registry.monitors[index].epoch_id
                && snapshot.config_revision == registry.monitors[index].config_revision
        }) {
            if registry.monitors[index].baseline_state != BaselineState::Initialized {
                registry.monitors[index].baseline_state = BaselineState::Initialized;
                self.write_registry(&registry, &lock)
                    .map_err(MonitorError::indeterminate)?;
            }
            return result(snapshot, after);
        }
        if registry.monitors[index].config_revision != ticket.registration.config_revision
            || registry.monitors[index].epoch_id != ticket.registration.epoch_id
        {
            return Err(MonitorError::new("E_MONITOR_STALE_CONFIG"));
        }
        if previous.as_ref().map_or(0, |snapshot| snapshot.generation) != ticket.generation {
            return Err(MonitorError::new("E_MONITOR_STALE_CHECK"));
        }
        let declared = context.domain.declared();
        let runtime_changed = context
            .domain
            .runtime
            .as_ref()
            .zip(registry.monitors[index].observed_runtime.as_ref())
            .is_some_and(|(current, old)| current != old);
        if declared != registry.monitors[index].config.domain || runtime_changed {
            let entry = &mut registry.monitors[index];
            entry.config.domain = declared;
            entry.observed_runtime = context.domain.runtime.clone();
            entry.epoch_id = random_id();
            entry.config_revision = entry
                .config_revision
                .checked_add(1)
                .ok_or_else(|| MonitorError::new("E_MONITOR_LIMIT"))?;
            entry.baseline_state = BaselineState::NotStarted;
            entry.reset_reason = Some("comparison_domain_changed".into());
            self.write_registry(&registry, &lock)?;
        }
        if registry.monitors[index].observed_runtime.is_none() && context.domain.runtime.is_some() {
            registry.monitors[index].observed_runtime = context.domain.runtime.clone();
            self.write_registry(&registry, &lock)?;
        }
        if registry.monitors[index].baseline_state == BaselineState::NotStarted {
            registry.monitors[index].baseline_state = BaselineState::Started;
            self.write_registry(&registry, &lock)?;
        }
        let mut snapshot = super::reducer::begin(
            &registry.monitors[index],
            previous.as_ref(),
            &ticket.check_id,
            context.now,
        )?;
        snapshot.comparison_domain = context.domain.clone();
        if snapshot.comparison_domain.runtime.is_none() {
            snapshot.comparison_domain.runtime = registry.monitors[index].observed_runtime.clone();
        }
        super::reducer::apply(&mut snapshot, projection)?;
        super::reducer::retain(&mut snapshot, &self.options.limits, context.now);
        self.root.write(
            &Self::snapshot_name(&snapshot.monitor_id),
            &snapshot,
            CommitTarget::Checkpoint,
            self.options.limits.max_checkpoint_bytes,
            &self.observer,
            &lock,
        )?;
        if registry.monitors[index].baseline_state != BaselineState::Initialized {
            registry.monitors[index].baseline_state = BaselineState::Initialized;
            self.write_registry(&registry, &lock)
                .map_err(MonitorError::indeterminate)?;
        }
        self.observer
            .observe(CommitTarget::Checkpoint, CommitStage::BeforeResponse)
            .map_err(|_| MonitorError::new("E_MONITOR_RESPONSE_LOST").indeterminate())?;
        lock.check(&self.root)
            .map_err(MonitorError::indeterminate)?;
        result(&snapshot, after)
    }
}
fn result(
    snapshot: &super::state::Snapshot,
    after: Option<&super::state::EventReplayCursor>,
) -> MonitorResult<super::state::CheckResult> {
    let newly: Vec<_> = snapshot
        .events
        .iter()
        .filter(|event| {
            event.epoch_id == snapshot.epoch_id
                && event.sequence >= snapshot.last_check.first_sequence
        })
        .collect();
    let count = snapshot.last_check.event_count;
    let gap = count > newly.len() as u64;
    let replay = super::replay::page(snapshot, after).map_err(|mut error| {
        error.commit_status = CommitStatus::Committed;
        error
    })?;
    Ok(super::state::CheckResult {
        commit_status: CommitStatus::Committed,
        newly_committed_events: newly.into_iter().take(REPLAY_PAGE_SIZE).cloned().collect(),
        newly_committed_count: count,
        newly_committed_truncated: count > REPLAY_PAGE_SIZE as u64,
        newly_committed_gap: gap,
        replay,
        current: snapshot.summary(),
    })
}
