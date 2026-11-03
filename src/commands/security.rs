//! Thin CLI projection of the shared, operator-authorized security check.
use super::RenderDetail;
use crate::security_assessment::{
    ObservationDiagnostic,
    check::{CheckUpdatesRequest, authorize_and_run, check_json, check_text, failed_check},
    config::SecurityAuthority,
    qualification::schedule::AssessmentContinuation,
};

pub(super) async fn check_updates(args: &crate::cli::CheckUpdatesArgs) -> RenderDetail {
    let continuation = match args
        .continuation
        .as_deref()
        .map(AssessmentContinuation::parse)
        .transpose()
    {
        Ok(cursor) => cursor,
        Err(error) => return render(failed_check(error, 2)),
    };
    let Some(path) = &args.security_config else {
        return render(failed_check(
            ObservationDiagnostic::new(
                "E_SECURITY_CONFIG_REQUIRED",
                "Select trusted operator configuration with --security-config; a project does not implicitly grant source or interpreter authority.",
            ),
            3,
        ));
    };
    let authority = match SecurityAuthority::load(path) {
        Ok(authority) => authority,
        Err(error) => return render(failed_check(error, 3)),
    };
    let request = CheckUpdatesRequest {
        profile: args.profile.clone(),
        project: args.project.clone(),
        target: args.target,
        mode: args.mode,
        limits: None,
        max_cache_age_seconds: args.max_cache_age_seconds,
        fail_on: args.fail_on,
        continuation,
    };
    let authorized = match authority.prepare(&request, args.timeout_ms) {
        Ok(authorized) => authorized,
        Err(error) => return render(failed_check(error, 3)),
    };
    let observed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |time| time.as_secs());
    render(authorize_and_run(authorized, observed_at).await)
}
fn render(result: crate::security_assessment::check::CheckUpdatesResult) -> RenderDetail {
    RenderDetail::with_json(check_text(&result), check_json(&result))
        .with_process_exit_code(result.exit_code)
}

pub(super) async fn monitor(args: &crate::cli::MonitorArgs) -> RenderDetail {
    use crate::{
        cli::MonitorCommands,
        security_assessment::monitor::service::{
            MonitorAccessScope, MonitorRequest, MonitorResponse,
        },
    };
    let (operator, request) = match &args.command {
        MonitorCommands::List { operator, profile } => (
            operator,
            MonitorRequest::List {
                profile: profile.clone(),
                timeout_ms: operator.timeout_ms,
            },
        ),
        MonitorCommands::Add {
            operator,
            name,
            profile,
            project,
            target,
        } => (
            operator,
            MonitorRequest::Add {
                name: name.clone(),
                profile: profile.clone(),
                project: project.clone(),
                target: *target,
                timeout_ms: operator.timeout_ms,
            },
        ),
        MonitorCommands::Check {
            operator,
            monitor_id,
            after,
            mode,
            fail_on,
            max_cache_age_seconds,
        } => (
            operator,
            MonitorRequest::Check {
                monitor_id: monitor_id.clone(),
                after: after.clone(),
                mode: *mode,
                fail_on: *fail_on,
                max_cache_age_seconds: *max_cache_age_seconds,
                limits: None,
                timeout_ms: operator.timeout_ms,
            },
        ),
        MonitorCommands::Events {
            operator,
            monitor_id,
            after,
        } => (
            operator,
            MonitorRequest::Events {
                monitor_id: monitor_id.clone(),
                after: after.clone(),
                timeout_ms: operator.timeout_ms,
            },
        ),
        MonitorCommands::Configure {
            operator,
            monitor_id,
            expected_revision,
            profile,
        } => (
            operator,
            MonitorRequest::Configure {
                monitor_id: monitor_id.clone(),
                expected_revision: *expected_revision,
                profile: profile.clone(),
                timeout_ms: operator.timeout_ms,
            },
        ),
        MonitorCommands::Remove {
            operator,
            monitor_id,
        } => (
            operator,
            MonitorRequest::Remove {
                monitor_id: monitor_id.clone(),
                timeout_ms: operator.timeout_ms,
            },
        ),
    };
    let action = request.action();
    let failure = |error, code| render_monitor(MonitorResponse::failure(action, error, code));
    if let Err(error) = request.validate() {
        return failure(error, 2);
    }
    let Some(path) = &operator.security_config else {
        return failure(
            ObservationDiagnostic::new(
                "E_SECURITY_CONFIG_REQUIRED",
                "Select trusted operator configuration with --security-config.",
            ),
            3,
        );
    };
    let authority = match SecurityAuthority::load(path) {
        Ok(authority) => authority,
        Err(error) => return failure(error, 3),
    };
    let observed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |time| time.as_secs());
    render_monitor(
        crate::security_assessment::monitor::service::execute(
            std::sync::Arc::new(authority),
            request,
            MonitorAccessScope::default(),
            None,
            observed_at,
        )
        .await,
    )
}

fn render_monitor(
    result: crate::security_assessment::monitor::service::MonitorResponse,
) -> RenderDetail {
    RenderDetail::with_json(result.text(), result.json()).with_process_exit_code(result.exit_code)
}
