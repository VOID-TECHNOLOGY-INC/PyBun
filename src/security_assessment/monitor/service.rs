//! Explicit monitor operations shared by CLI and MCP. Persist before rendering.
mod blocking;
#[cfg(test)]
mod blocking_tests;
use blocking::task;
mod request;
mod result;
pub use request::MonitorRequest;
pub use result::MonitorResponse;

use super::*;
use crate::security_assessment::{
    InventoryBackend, ObservationDiagnostic,
    check::{CheckMode, CheckTarget, CheckUpdatesRequest, RawCheckContext, authorize_prepared},
    config::{DeclaredMonitorProfile, MonitorStateAccess, SecurityAuthority},
    http::EvidenceFreshness,
    qualification::service::{
        AssessmentOptions, assess_inventory_with_history, attach_project_provenance,
        continuation_matches_inventory, observe_project_inventory,
    },
};
use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

/// Trusted adapter restrictions; never deserialized from a request or state.
#[derive(Clone, Default)]
pub(crate) struct MonitorAccessScope {
    pub(crate) profiles: Option<BTreeSet<String>>,
    pub(crate) backends: Option<BTreeSet<String>>,
    pub(crate) directories: Option<Vec<PathBuf>>,
}
impl MonitorAccessScope {
    pub(crate) fn permits(&self, profile: &DeclaredMonitorProfile) -> bool {
        let backend = match profile.backend {
            InventoryBackend::Uv => "uv",
            InventoryBackend::Native => "native",
        };
        self.profiles
            .as_ref()
            .is_none_or(|ids| ids.contains(&profile.profile_id))
            && self
                .backends
                .as_ref()
                .is_none_or(|ids| ids.contains(backend))
            && self.directories.as_ref().is_none_or(|roots| {
                [&profile.project_root, &profile.environment_root]
                    .iter()
                    .all(|path| roots.iter().any(|root| path.starts_with(root)))
            })
    }
}

fn diagnostic(code: &str) -> ObservationDiagnostic {
    ObservationDiagnostic::new(
        code,
        "The explicit monitor operation could not complete; no missing evidence proves a finding resolved.",
    )
}
fn inaccessible() -> ObservationDiagnostic {
    diagnostic("E_MONITOR_UNAVAILABLE")
}
fn unavailable(request: &MonitorRequest) -> MonitorResponse {
    if matches!(request, MonitorRequest::Remove { .. }) {
        let mut response = MonitorResponse::empty("remove");
        response.removed = Some(false);
        response
    } else {
        MonitorResponse::failure(request.action(), inaccessible(), 3)
    }
}
fn declared(profile: &DeclaredMonitorProfile) -> ComparisonDomain {
    ComparisonDomain {
        project_root: profile.project_root.clone(),
        environment_root: profile.environment_root.clone(),
        backend: profile.backend,
        target: profile.target,
        scope: profile.scope.clone(),
        runtime: None,
        source_policy_digest: profile.source_policy_digest.clone(),
        provider_config_digest: profile.provider_config_digest.clone(),
        index_config_digest: profile.index_config_digest.clone(),
        observation_version: profile.observation_version,
        authoritative_providers: profile.authoritative_providers.clone(),
    }
}
fn configuration(profile: &DeclaredMonitorProfile, name: String) -> MonitorConfig {
    MonitorConfig {
        profile_id: profile.profile_id.clone(),
        name,
        freshness_ttl_seconds: profile.max_cache_age_seconds,
        include_prereleases: profile.include_prereleases,
        domain: declared(profile),
    }
}

fn prepare_authorized_ticket(
    store: &MonitorStore,
    expected: Registration,
    replacement: Option<MonitorConfig>,
) -> MonitorResult<PreparedCheck> {
    let expected = if let Some(config) = replacement {
        store.configure(&expected.monitor_id, expected.config_revision, config)?
    } else {
        expected
    };
    store.prepare_check_expected(&expected)
}

fn narrow_store_deadline(
    mut store: Arc<MonitorStore>,
    deadline: Instant,
) -> MonitorResult<Arc<MonitorStore>> {
    let unique =
        Arc::get_mut(&mut store).ok_or_else(|| MonitorError::new("E_MONITOR_STATE_BUSY"))?;
    unique.options.deadline = Some(
        unique
            .options
            .deadline
            .map_or(deadline, |existing| existing.min(deadline)),
    );
    Ok(store)
}

fn read_authorized_events(
    store: &MonitorStore,
    expected: &Registration,
    after: Option<&EventReplayCursor>,
) -> MonitorResult<ReplayPage> {
    store.events_expected(expected, after)
}
fn remove_authorized_registration(
    store: &MonitorStore,
    expected: &Registration,
) -> MonitorResult<bool> {
    store.remove_expected(expected)
}
fn configure_authorized_registration(
    store: &MonitorStore,
    expected: &Registration,
    client_revision: u64,
    replacement: MonitorConfig,
) -> MonitorResult<Registration> {
    if client_revision != expected.config_revision {
        return Err(MonitorError::new("E_MONITOR_STALE_CONFIG"));
    }
    store.configure(&expected.monitor_id, expected.config_revision, replacement)
}

/// The caller has already completed transport admission. No durable audit or
/// target/provider effect occurs before current frozen authority is checked.
pub(crate) async fn execute(
    authority: Arc<SecurityAuthority>,
    request: MonitorRequest,
    scope: MonitorAccessScope,
    operator_timeout_ms: Option<u64>,
    observed_at: u64,
) -> MonitorResponse {
    let action = request.action();
    if let Err(error) = request.validate() {
        return MonitorResponse::failure(action, error, 2);
    }
    let state = match authority.monitor_state_grant() {
        Ok(state) => state,
        Err(error) => return MonitorResponse::failure(action, error, 3),
    };
    let max_output = state.max_output_bytes();
    let started = Instant::now();
    let timeout = [
        Some(state.limits().total_timeout_ms),
        operator_timeout_ms,
        request.timeout_ms(),
        match &request {
            MonitorRequest::Check {
                limits: Some(limits),
                ..
            } => Some(limits.total_timeout_ms),
            _ => None,
        },
    ]
    .into_iter()
    .flatten()
    .min()
    .unwrap_or(60_000);
    let deadline = started + Duration::from_millis(timeout);
    let response = execute_inner(
        authority,
        request,
        scope,
        state,
        started,
        deadline,
        observed_at,
    )
    .await;
    response.bounded(max_output)
}

async fn execute_inner(
    authority: Arc<SecurityAuthority>,
    request: MonitorRequest,
    scope: MonitorAccessScope,
    state: crate::security_assessment::config::MonitorStateGrant,
    started: Instant,
    deadline: Instant,
    observed_at: u64,
) -> MonitorResponse {
    let action = request.action();
    let mut deadline = deadline;
    if let Some(id) = request.profile() {
        if let Ok(profile) = authority.monitor_profile(Some(id)) {
            deadline =
                deadline.min(started + Duration::from_millis(profile.limits.total_timeout_ms));
        }
    } else if matches!(request, MonitorRequest::Add { .. })
        && let Ok(profile) = authority.monitor_profile(None)
    {
        deadline = deadline.min(started + Duration::from_millis(profile.limits.total_timeout_ms));
    }
    let (after, malformed_cursor) = match request.after().map(EventReplayCursor::parse).transpose()
    {
        Ok(after) => (after, false),
        Err(_) => (None, true),
    };
    // Client-selected configuration references are checked before even opening
    // the approved state root. Stored IDs are resolved only after state admission.
    if let Some(profile) = request.profile() {
        match authority.monitor_profile(Some(profile)) {
            Ok(profile) if scope.permits(&profile) => {}
            _ => return MonitorResponse::failure(action, inaccessible(), 3),
        }
    }
    if let MonitorRequest::Add {
        profile,
        project,
        target,
        ..
    } = &request
    {
        if *target != CheckTarget::Installed {
            return MonitorResponse::failure(
                action,
                diagnostic("E_SECURITY_TARGET_UNSUPPORTED"),
                3,
            );
        }
        let selected = match authority.monitor_profile(profile.as_deref()) {
            Ok(profile) if scope.permits(&profile) => profile,
            _ => return MonitorResponse::failure(action, inaccessible(), 3),
        };
        let project = project.clone();
        if let (Some(path), Some(roots)) = (&project, &scope.directories) {
            let path = if path.is_absolute() {
                path.clone()
            } else {
                std::env::current_dir().unwrap_or_default().join(path)
            };
            if path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
                || !roots.iter().any(|root| path.starts_with(root))
            {
                return MonitorResponse::failure(action, inaccessible(), 3);
            }
        }
        if let Err(error) = task(deadline, false, move || {
            if let Some(project) = project
                && project
                    .canonicalize()
                    .map_err(|_| MonitorError::new("E_MONITOR_INPUT"))?
                    != selected.project_root
            {
                return Err(MonitorError::new("E_MONITOR_INPUT"));
            }
            selected
                .authorize(deadline)
                .map_err(|error| MonitorError::new(&error.code))
        })
        .await
        {
            return MonitorResponse::error(action, error);
        }
    }
    let create = matches!(request, MonitorRequest::Add { .. });
    let access = if request.writes() {
        MonitorStateAccess::WriteCreate
    } else {
        MonitorStateAccess::Read
    };
    let write = request.writes();
    let opened = task(deadline, write, move || {
        let authorized = state
            .authorize(access, deadline)
            .map_err(|error| MonitorError::new(&error.code))?;
        if !authorized.exists() && !create {
            return Ok(None);
        }
        let mut options = StoreOptions::new(authorized.root().to_path_buf());
        options.deadline = Some(deadline);
        let store = if create {
            let parent = state
                .creation_parent(deadline)
                .map_err(|error| MonitorError::new(&error.code))?;
            options.root = parent.root().to_path_buf();
            MonitorStore::create_from_parent(options, parent.parent_path(), parent.parent_handle())?
        } else {
            MonitorStore::open(options)?
        };
        {
            state
                .pin_created_root(
                    &store
                        .root_handle()
                        .map_err(|_| MonitorError::new("E_MONITOR_STATE_ROOT"))?,
                    deadline,
                )
                .map_err(|error| MonitorError::new(&error.code))?;
        }
        Ok(Some(Arc::new(store)))
    })
    .await;
    let store = match opened {
        Ok(Some(store)) => store,
        Ok(None) => {
            return if matches!(request, MonitorRequest::List { .. }) {
                MonitorResponse::empty(action)
            } else {
                unavailable(&request)
            };
        }
        Err(error) => return MonitorResponse::error(action, error),
    };
    // This bounded registry read is authorized by this action. Filtering is
    // applied before any registration or aggregate count reaches the caller.
    let registry = match task(deadline, false, {
        let store = store.clone();
        move || store.list()
    })
    .await
    {
        Ok(registry) => registry,
        Err(error) => return MonitorResponse::error(action, error),
    };
    if let MonitorRequest::List { profile, .. } = &request {
        let mut result = MonitorResponse::empty(action);
        for registration in registry {
            if profile
                .as_ref()
                .is_some_and(|id| id != &registration.config.profile_id)
            {
                continue;
            }
            let Ok(current) = authority.monitor_profile(Some(&registration.config.profile_id))
            else {
                continue;
            };
            if scope.permits(&current)
                && declared(&current) == registration.config.domain.declared()
            {
                let output_limit = current.max_output_bytes;
                let profile_deadline =
                    deadline.min(started + Duration::from_millis(current.limits.total_timeout_ms));
                let valid = task(profile_deadline, false, move || {
                    current
                        .authorize(profile_deadline)
                        .map_err(|error| MonitorError::new(&error.code))
                })
                .await;
                match valid {
                    Ok(()) => {
                        result.output_limit = result.output_limit.min(output_limit);
                        result.registrations.push(registration);
                    }
                    Err(error) if error.code == "E_SECURITY_DEADLINE" => {
                        result.exit_code = 3;
                        result.status = "partial".into();
                        result.diagnostics.push(diagnostic("E_SECURITY_DEADLINE"));
                        return result;
                    }
                    Err(_) => {}
                }
            }
        }
        return result;
    }
    if let MonitorRequest::Add { name, profile, .. } = &request {
        let current = match authority.monitor_profile(profile.as_deref()) {
            Ok(current) if scope.permits(&current) => current,
            _ => return MonitorResponse::failure(action, inaccessible(), 3),
        };
        let output_limit = current.max_output_bytes;
        let config = configuration(&current, name.clone());
        return match task(deadline, true, move || {
            current
                .authorize(deadline)
                .map_err(|error| MonitorError::new(&error.code))?;
            store.register(config)
        })
        .await
        {
            Ok(registration) => {
                let mut result = MonitorResponse::empty(action);
                result.registration = Some(registration);
                result.commit_status = CommitStatus::Committed;
                result.output_limit = output_limit;
                result
            }
            Err(error) => MonitorResponse::error(action, error),
        };
    }
    let Some(registration) = registry
        .into_iter()
        .find(|registration| Some(registration.monitor_id.as_str()) == request.id())
    else {
        return unavailable(&request);
    };
    let current = match authority.monitor_profile(Some(&registration.config.profile_id)) {
        Ok(current) if scope.permits(&current) => current,
        _ => return unavailable(&request),
    };
    let changed = configuration(&current, registration.config.name.clone()) != registration.config;
    if changed
        && !matches!(
            request,
            MonitorRequest::Check { .. } | MonitorRequest::Configure { .. }
        )
    {
        return unavailable(&request);
    }
    let profile_deadline =
        (started + Duration::from_millis(current.limits.total_timeout_ms)).min(deadline);
    let output_limit = current.max_output_bytes;
    let store = match narrow_store_deadline(store, profile_deadline) {
        Ok(store) => store,
        Err(error) => return MonitorResponse::error(action, error),
    };
    if malformed_cursor {
        if changed {
            return unavailable(&request);
        }
        let mut response = match task(profile_deadline, false, move || {
            current
                .authorize(profile_deadline)
                .map_err(|error| MonitorError::new(&error.code))?;
            let mut error = MonitorError::new("E_MONITOR_CURSOR_SCOPE");
            error.replay = match read_authorized_events(&store, &registration, None) {
                Ok(replay) => Some(Box::new(replay)),
                Err(existing) if existing.replay.is_some() => existing.replay,
                Err(existing) => return Err(existing),
            };
            Err::<(), _>(error)
        })
        .await
        {
            Err(error) => MonitorResponse::error(action, error),
            Ok(()) => unreachable!("malformed cursor always fails"),
        };
        response.output_limit = output_limit;
        return response;
    }
    let mut response = match request {
        MonitorRequest::Events { .. } => {
            match task(profile_deadline, false, move || {
                current
                    .authorize(profile_deadline)
                    .map_err(|error| MonitorError::new(&error.code))?;
                read_authorized_events(&store, &registration, after.as_ref())
            })
            .await
            {
                Ok(replay) => {
                    let mut result = MonitorResponse::empty(action);
                    if !replay.current.complete {
                        result.status = "partial".into();
                        result.exit_code = 3;
                    }
                    result.current = Some(replay.current.clone());
                    result.replay = Some(replay);
                    result.require_resynchronization();
                    result
                }
                Err(error) => MonitorResponse::error(action, error),
            }
        }
        MonitorRequest::Remove { .. } => match task(profile_deadline, true, move || {
            current
                .authorize(profile_deadline)
                .map_err(|error| MonitorError::new(&error.code))?;
            remove_authorized_registration(&store, &registration)
        })
        .await
        {
            Ok(removed) => {
                let mut result = MonitorResponse::empty(action);
                result.removed = Some(removed);
                result.commit_status = CommitStatus::Committed;
                result
            }
            Err(error) => MonitorResponse::error(action, error),
        },
        MonitorRequest::Configure {
            expected_revision,
            profile,
            ..
        } => {
            // A configured profile grants checks of its own target. It does not
            // let a client rebind an existing monitor to a different profile.
            if profile != registration.config.profile_id {
                return MonitorResponse::failure(action, inaccessible(), 3);
            }
            let replacement = match authority.monitor_profile(Some(&profile)) {
                Ok(profile) if scope.permits(&profile) => profile,
                _ => return MonitorResponse::failure(action, inaccessible(), 3),
            };
            let config = configuration(&replacement, registration.config.name.clone());
            match task(profile_deadline, true, move || {
                current
                    .authorize(profile_deadline)
                    .map_err(|error| MonitorError::new(&error.code))?;
                replacement
                    .authorize(profile_deadline)
                    .map_err(|error| MonitorError::new(&error.code))?;
                configure_authorized_registration(&store, &registration, expected_revision, config)
            })
            .await
            {
                Ok(registration) => {
                    let mut result = MonitorResponse::empty(action);
                    result.registration = Some(registration);
                    result.commit_status = CommitStatus::Committed;
                    result
                }
                Err(error) => MonitorResponse::error(action, error),
            }
        }
        MonitorRequest::Check {
            mode,
            fail_on,
            max_cache_age_seconds,
            limits,
            ..
        } => {
            let check_request = CheckUpdatesRequest {
                profile: Some(current.profile_id.clone()),
                mode,
                fail_on,
                max_cache_age_seconds,
                limits,
                ..Default::default()
            };
            let prepared = match authority.prepare(&check_request, None) {
                Ok(prepared) => prepared.with_deadline(profile_deadline),
                Err(error) => return MonitorResponse::failure(action, error, 3),
            };
            let authorized = match authorize_prepared(prepared).await {
                Ok(authorized) => authorized,
                Err(error) => return MonitorResponse::failure(action, error, 3),
            };
            let ticket = match task(profile_deadline, true, {
                let store = store.clone();
                let replacement =
                    changed.then(|| configuration(&current, registration.config.name.clone()));
                move || prepare_authorized_ticket(&store, registration, replacement)
            })
            .await
            {
                Ok(ticket) => ticket,
                Err(error) => return MonitorResponse::error(action, error),
            };
            check_observation(
                store,
                ticket,
                current,
                authorized,
                changed,
                after,
                mode,
                observed_at,
                profile_deadline,
            )
            .await
        }
        _ => unreachable!("list/add handled before stored registration lookup"),
    };
    response.output_limit = output_limit;
    response
}

#[allow(clippy::too_many_arguments)]
async fn check_observation(
    store: Arc<MonitorStore>,
    ticket: PreparedCheck,
    profile: DeclaredMonitorProfile,
    authorized: crate::security_assessment::config::AuthorizedCheck,
    changed: bool,
    after: Option<EventReplayCursor>,
    mode: CheckMode,
    observed_at: u64,
    deadline: Instant,
) -> MonitorResponse {
    let mut context = CheckContext {
        domain: declared(&profile),
        mode: if mode == CheckMode::Offline {
            ObservationMode::Offline
        } else {
            ObservationMode::Online
        },
        inventory_freshness: EvidenceFreshness::default(),
        now: observed_at,
        deadline,
    };
    let raw = match RawCheckContext::new(authorized, observed_at) {
        Ok(raw) => raw,
        Err(error) => return failure_commit(store, ticket, context, after, error).await,
    };
    let inventory = match observe_project_inventory(&raw.session, &raw.authorized.inventory).await {
        Ok(inventory) => inventory,
        Err(error) => return failure_commit(store, ticket, context, after, error).await,
    };
    // Inventory is a current helper observation even when provider mode is
    // offline; online/offline authority is represented separately in context.
    context.inventory_freshness = EvidenceFreshness::default();
    let mut options = if changed {
        AssessmentOptions {
            include_prereleases: profile.include_prereleases,
            ..Default::default()
        }
    } else {
        match ticket.assessment_options(&inventory) {
            Ok(options) => options,
            Err(error) => return MonitorResponse::error("check", error),
        }
    };
    let mut history = vec![];
    if !changed {
        for package in &inventory.packages {
            let key = match super::projection::logical_package_key(package) {
                Ok(key) => key,
                Err(error) => return MonitorResponse::error("check", error),
            };
            for witness in ticket
                .known_advisories()
                .iter()
                .filter(|witness| witness.package_key == key)
            {
                history.push(crate::security_assessment::osv::KnownAdvisoryId {
                    instance_id: package.instance_id.clone(),
                    provider_id: witness.provider_id.clone(),
                    record_id: witness.record_id.clone(),
                });
            }
        }
    }
    let restarted = match continuation_matches_inventory(
        &inventory,
        &raw.authorized.inventory.source_policy,
        &raw.authorized.providers,
        &raw.authorized.sources,
        &options,
    ) {
        Ok(current) => !current,
        Err(error) => return failure_commit(store, ticket, context, after, error).await,
    };
    if restarted {
        options.continuation = None;
    }
    let mut assessment = match assess_inventory_with_history(
        &raw.session,
        &inventory,
        &raw.authorized.inventory.source_policy,
        &raw.authorized.providers,
        &raw.authorized.sources,
        &options,
        &history,
    )
    .await
    {
        Ok(assessment) => assessment,
        Err(error) => return failure_commit(store, ticket, context, after, error).await,
    };
    if restarted {
        assessment
            .diagnostics
            .push(diagnostic("E_MONITOR_TRAVERSAL_RESTARTED"));
    }
    let provenance = raw
        .authorized
        .provenance
        .as_ref()
        .map(|(request, bindings)| (request, bindings.as_slice()));
    if let Err(error) = attach_project_provenance(
        &raw.session,
        &raw.authorized.inventory,
        &mut assessment,
        provenance,
    )
    .await
    {
        return failure_commit(store, ticket, context, after, error).await;
    }
    if let Some(target) = &inventory.target {
        context.domain.runtime = Some(RuntimeIdentity::from_target(target));
    }
    let max_output_bytes = raw.authorized.max_output_bytes;
    let fail_on = raw.authorized.fail_on;
    let check = match raw.prepare_observed(assessment).await {
        Ok(check) => check,
        Err(check) => {
            let error = check
                .diagnostics
                .first()
                .cloned()
                .unwrap_or_else(|| diagnostic("E_SECURITY_DEADLINE"));
            let mut response = MonitorResponse::failure("check", error, 3);
            response.status = "partial".into();
            response.check = Some(crate::security_assessment::check::bound_output(
                *check,
                max_output_bytes,
            ));
            return response;
        }
    };
    let mut fallback = crate::security_assessment::check::deferred_observation_summary(
        check
            .assessment
            .as_ref()
            .expect("completed unbounded assessment"),
        check.profile_id.as_deref().expect("authorized profile"),
        check.policy_digest.as_deref().expect("authorized policy"),
        fail_on,
        max_output_bytes,
        diagnostic("E_SECURITY_DEADLINE"),
    );
    fallback.assessment_id = check.assessment_id.clone();
    fallback.observation_id = check.observation_id.clone();
    let completed = task(deadline, true, move || {
        let outcome = store.commit_check(
            &ticket,
            check
                .assessment
                .as_ref()
                .expect("unbounded prepared assessment"),
            context,
            after.as_ref(),
        );
        Ok((check, outcome))
    })
    .await;
    let (check, outcome) = match completed {
        Ok(completed) => completed,
        Err(error) => {
            let mut response = MonitorResponse::error("check", error);
            response.check = Some(crate::security_assessment::check::bound_output(
                fallback,
                max_output_bytes,
            ));
            return response;
        }
    };
    let check = crate::security_assessment::check::bound_output(check, max_output_bytes);
    let mut response = match outcome {
        Ok(committed) => {
            let mut response = MonitorResponse::checked("check", committed);
            response.exit_code = if response.exit_code == 3 || check.exit_code == 3 {
                3
            } else {
                check.exit_code
            };
            response.status = if response.exit_code == 3 {
                "partial"
            } else {
                "complete"
            }
            .into();
            response
        }
        Err(error) => MonitorResponse::error("check", error),
    };
    response.check = Some(check);
    response
}

async fn failure_commit(
    store: Arc<MonitorStore>,
    ticket: PreparedCheck,
    context: CheckContext,
    after: Option<EventReplayCursor>,
    error: ObservationDiagnostic,
) -> MonitorResponse {
    let code = error.code.clone();
    match task(context.deadline, true, move || {
        store.commit_failure(
            &ticket,
            &[MonitorDiagnostic {
                code,
                scope: "observation".into(),
            }],
            context,
            after.as_ref(),
        )
    })
    .await
    {
        Ok(result) => {
            let mut response = MonitorResponse::checked("check", result);
            response.status = "partial".into();
            response.exit_code = 3;
            response.diagnostics.push(error);
            response
        }
        Err(failure) => MonitorResponse::error("check", failure),
    }
}
