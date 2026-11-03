//! Durable-result projection, bounded responses and local human notifications.
use super::super::*;
use super::diagnostic;
use crate::security_assessment::{
    ObservationDiagnostic,
    check::{CheckUpdatesResult, check_wire_fits},
};
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Serialize)]
pub struct MonitorResponse {
    pub contract_version: &'static str,
    pub operation: &'static str,
    pub action: String,
    pub status: String,
    pub exit_code: i32,
    pub commit_status: CommitStatus,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub registrations: Vec<Registration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration: Option<Registration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current: Option<MonitorSummary>,
    pub newly_committed_events: Vec<MonitorEvent>,
    pub newly_committed_count: u64,
    pub newly_committed_truncated: bool,
    pub newly_committed_gap: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay: Option<ReplayPage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check: Option<CheckUpdatesResult>,
    pub diagnostics: Vec<ObservationDiagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub omitted: Option<Value>,
    #[serde(skip)]
    pub(super) output_limit: usize,
}
impl MonitorResponse {
    pub(super) fn empty(action: &str) -> Self {
        Self {
            contract_version: "2",
            operation: "security_monitor",
            action: action.into(),
            status: "complete".into(),
            exit_code: 0,
            commit_status: CommitStatus::NotCommitted,
            registrations: vec![],
            registration: None,
            removed: None,
            current: None,
            newly_committed_events: vec![],
            newly_committed_count: 0,
            newly_committed_truncated: false,
            newly_committed_gap: false,
            replay: None,
            check: None,
            diagnostics: vec![],
            omitted: None,
            output_limit: usize::MAX,
        }
    }
    pub(super) fn error(action: &str, error: MonitorError) -> Self {
        let mut response = Self::failure(action, diagnostic(&error.code), 3);
        response.commit_status = error.commit_status;
        if let Some(receipt) = error.receipt {
            response.newly_committed_events = receipt.newly_committed_events;
            response.newly_committed_count = receipt.newly_committed_count;
            response.newly_committed_truncated = receipt.newly_committed_truncated;
            response.newly_committed_gap = receipt.newly_committed_gap;
        }
        if let Some(replay) = error.replay {
            response.current = Some(replay.current.clone());
            response.replay = Some(*replay);
        }
        response
    }
    pub fn failure(action: &str, error: ObservationDiagnostic, exit_code: i32) -> Self {
        let mut result = Self::empty(action);
        result.status = "error".into();
        result.exit_code = exit_code;
        result.diagnostics.push(error);
        result
    }
    pub(super) fn checked(action: &str, result: CheckResult) -> Self {
        let mut response = Self::empty(action);
        response.commit_status = result.commit_status;
        response.newly_committed_events = result.newly_committed_events;
        response.newly_committed_count = result.newly_committed_count;
        response.newly_committed_truncated = result.newly_committed_truncated;
        response.newly_committed_gap = result.newly_committed_gap;
        if !result.current.complete {
            response.exit_code = 3;
            response.status = "partial".into();
        }
        response.current = Some(result.current);
        response.replay = Some(result.replay);
        response
    }
    pub fn bounded(mut self, max_bytes: usize) -> Self {
        let max_bytes = max_bytes.min(self.output_limit);
        self.output_limit = max_bytes;
        if check_wire_fits(&self, max_bytes, 2048) {
            return self;
        }
        let omitted = json!({"registrations":self.registrations.len(),"current_findings":self.current.as_ref().map_or(0,|s|s.findings.len()),"newly_committed_events":self.newly_committed_events.len(),"replay_events":self.replay.as_ref().map_or(0,|r|r.events.len()),"assessment_details":usize::from(self.check.is_some()),"threshold_matches":self.check.as_ref().map_or(0,|check|check.threshold_match_count),"assessment_omissions":self.check.as_ref().and_then(|check|check.omitted.as_ref())});
        self.omitted = Some(
            json!({"assessment_details":usize::from(self.check.is_some()),"threshold_matches":self.check.as_ref().map_or(0,|check|check.threshold_match_count),"assessment_omissions":self.check.as_ref().and_then(|check|check.omitted.as_ref())}),
        );
        self.check = None;
        self.status = "partial".into();
        self.exit_code = 3;
        if !self
            .diagnostics
            .iter()
            .any(|item| item.code == "E_SECURITY_OUTPUT_LIMIT")
        {
            self.diagnostics.push(diagnostic("E_SECURITY_OUTPUT_LIMIT"));
        }
        // Prefer committed findings/events over duplicate one-shot details.
        if check_wire_fits(&self, max_bytes, 2048) {
            return self;
        }
        self.omitted = Some(omitted);
        self.registrations.clear();
        self.registration = None;
        self.check = None;
        if let Some(current) = &mut self.current {
            current.findings.clear();
            current.diagnostics.clear();
        }
        self.newly_committed_events.clear();
        self.newly_committed_truncated = self.newly_committed_count > 0;
        if let Some(replay) = &mut self.replay {
            replay.events.clear();
            replay.current.findings.clear();
            replay.current.diagnostics.clear();
            replay.next_cursor = None;
            replay.has_more = true;
        }
        self.status = "partial".into();
        self.exit_code = 3;
        if !self
            .diagnostics
            .iter()
            .any(|item| item.code == "E_SECURITY_OUTPUT_LIMIT")
        {
            self.diagnostics.push(diagnostic("E_SECURITY_OUTPUT_LIMIT"));
        }
        // The durable cursor and full baseline remain in state; retry the same
        // input cursor. Never advance a cursor past omitted events.
        if !check_wire_fits(&self, max_bytes, 128) {
            self.replay = None;
        }
        self
    }
    pub(crate) fn output_limit(&self) -> usize {
        self.output_limit
    }

    pub fn json(&self) -> Value {
        serde_json::to_value(self).expect("typed monitor response")
    }
    pub fn text(&self) -> String {
        let mut lines = vec![format!(
            "Security monitor {}: {} (commit {:?}).",
            self.action, self.status, self.commit_status
        )];
        for registration in &self.registrations {
            lines.push(format!(
                "{} {}",
                registration.monitor_id, registration.config.name
            ));
        }
        if let Some(registration) = &self.registration {
            lines.push(format!(
                "{} {}",
                registration.monitor_id, registration.config.name
            ));
        }
        if let Some(current) = &self.current {
            for finding in current.findings.iter().filter(|finding| finding.active) {
                lines.push(format!(
                    "{}: unresolved advisory {}.",
                    finding.package_name,
                    finding.aliases.join(", ")
                ));
                if !finding.complete
                    || finding
                        .evidence
                        .iter()
                        .any(|evidence| !evidence.currently_fresh)
                {
                    lines.push(
                        "Finding uses retained or incomplete evidence; freshness is not assumed."
                            .into(),
                    );
                }
                if let Some(candidate) = &finding.candidate {
                    let label = if candidate.qualified_remediation {
                        "published remediation candidate"
                    } else if candidate.publication_available {
                        "observed published version; remediation unconfirmed"
                    } else {
                        "observed version; publication unavailable and remediation unconfirmed"
                    };
                    let constraints=match candidate.constraint_status {
                        crate::security_assessment::qualification::constraints::ConstraintStatus::PassesKnownConstraints=>"passes known direct constraints",
                        crate::security_assessment::qualification::constraints::ConstraintStatus::BlockedByKnownConstraint=>"blocked by a known direct constraint",
                        crate::security_assessment::qualification::constraints::ConstraintStatus::Unknown=>"direct constraints remain unknown",
                    };
                    lines.push(format!(
                        "{label} {}; {constraints}; last_confirmed_at={}.",
                        candidate.version, candidate.last_confirmed_at
                    ));
                    if !candidate.publication_available && candidate.qualified_remediation {
                        lines.push("Previously confirmed candidate; current publication availability is not confirmed.".into());
                    }
                } else {
                    lines.push(format!(
                        "{}: no confirmed candidate for this finding.",
                        finding.package_name
                    ));
                }
            }
        }
        for event in &self.newly_committed_events {
            let event_type = serde_json::to_value(event.event_type).expect("event type");
            lines.push(format!(
                "Local event {}: {} observed_at={} (observation time is not release time).",
                event.event_id,
                event_type.as_str().unwrap_or("unknown"),
                event.observed_at,
            ));
        }
        for error in &self.diagnostics {
            lines.push(format!("{}: {}", error.code, error.message));
        }
        lines.push("Run-once observation; resolution not checked and verification not run.".into());
        lines.push("Missing fix information does not prove no upstream fix exists.".into());
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn human_summary_distinguishes_qualified_candidates_constraints_and_retained_facts() {
        let mut response = MonitorResponse::empty("check");
        response.current=Some(serde_json::from_value(json!({
            "monitor_id":"monitor","epoch_id":"epoch","config_revision":1,"generation":1,"initialized":true,"complete":false,"observed_at":20,"diagnostics":[],
            "findings":[{"finding_id":"finding","package_key":"key","package_name":"six","source":{"id":"public","auth_scope_id":"public","kind":"public_registry"},"scope_variant":"installed","aliases":["HIGH-ONE"],"vulnerable_versions":["1.0"],"active":true,"observed_affected":"yes","complete":false,"severity":"high","last_known_severity":"high","candidate":{"source_id":"public","auth_scope_id":"public","version":"22.0","artifacts":[],"qualified_remediation":true,"publication_available":true,"constraint_status":"unknown","last_confirmed_at":10},"evidence":[],"related_lineages":[],"semantic_digest":"digest"}]
        })).unwrap());
        response.newly_committed_events.push(MonitorEvent {
            event_id: "event-stable".into(),
            monitor_id: "monitor".into(),
            epoch_id: "epoch".into(),
            sequence: 1,
            event_type: MonitorEventType::FixCandidateAvailable,
            observed_at: 20,
            finding_id: Some("finding".into()),
            package_key: Some("key".into()),
            reason: None,
            candidate_version: Some("22.0".into()),
            related_lineages: vec![],
        });
        let text = response.text();
        assert!(
            text.contains("published remediation candidate 22.0"),
            "{text}"
        );
        assert!(text.contains("direct constraints remain unknown"), "{text}");
        assert!(text.contains("retained or incomplete evidence"), "{text}");
        assert!(
            text.contains("event-stable")
                && text.contains("fix_candidate_available")
                && text.contains("observed_at=20"),
            "{text}"
        );
        assert!(
            text.contains("observation time is not release time"),
            "{text}"
        );
        response.current.as_mut().unwrap().findings[0].candidate = None;
        let text = response.text();
        assert!(
            text.contains("no confirmed candidate")
                && text.contains("Missing fix information does not prove no upstream fix exists"),
            "{text}"
        );
        assert!(text.contains("resolution not checked") && text.contains("verification not run"));
    }
}
