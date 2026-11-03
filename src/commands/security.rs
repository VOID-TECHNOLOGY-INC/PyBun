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
