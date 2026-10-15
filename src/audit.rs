//! Shared OSV-based vulnerability scanning primitives.
//!
//! Used by both the MCP `pybun_audit` tool (`src/mcp.rs`) and the CLI
//! `pybun audit` command (`src/commands/maintenance.rs`) so the two surfaces
//! query the same OSV endpoint, apply the same severity normalization, and
//! report the same counts (Issue #316, in the spirit of the PR-A3 MCP/CLI
//! unification goal).

use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command as ProcessCommand;

/// A package as reported by `pip list --format=json`.
#[derive(Debug, Clone)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
}

/// A single vulnerability affecting an installed package, at or above the
/// requested severity threshold.
#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub package: String,
    pub installed_version: String,
    pub vulnerability_id: String,
    pub severity: String,
    pub description: String,
    pub fix_version: Option<String>,
}

/// Result of scanning a set of installed packages against OSV.
#[derive(Debug, Clone, Default)]
pub struct AuditReport {
    /// Number of packages submitted to OSV.
    pub scanned: usize,
    /// Packages OSV did not return a result for (partial/mismatched response).
    pub unscanned: usize,
    /// Vulnerabilities at or above the requested severity threshold.
    pub vulnerabilities: Vec<Vulnerability>,
}

impl AuditReport {
    pub fn count_at_severity(&self, severity: &str) -> usize {
        self.vulnerabilities
            .iter()
            .filter(|v| v.severity == severity)
            .count()
    }

    /// Highest severity level present in the report, if any vulnerabilities
    /// were found.
    pub fn highest_severity_level(&self) -> Option<u8> {
        self.vulnerabilities
            .iter()
            .map(|v| severity_level(&v.severity))
            .max()
    }
}

/// Default OSV endpoint, overridable via `PYBUN_OSV_URL` (tests point this at
/// a mock server).
pub fn default_osv_url() -> String {
    std::env::var("PYBUN_OSV_URL")
        .unwrap_or_else(|_| "https://api.osv.dev/v1/querybatch".to_string())
}

/// List installed packages via standard-library metadata for uv projects,
/// or `pip list --format=json` for native compatibility. Returns `Err` if inspection exited
/// non-zero, or produced output that isn't valid JSON, so callers doing
/// CI-gated scans (`--fail-on`) can distinguish "verified zero packages"
/// from "failed to inspect the environment" rather than silently treating
/// both as a clean scan.
pub fn list_installed_packages(python_path: &Path) -> Result<Vec<InstalledPackage>, String> {
    let uv_environment = !crate::backend::native_selected()
        && python_path.ancestors().any(|p| p.join("uv.lock").is_file());
    let args = if uv_environment {
        vec![
            "-I",
            "-c",
            "import importlib.metadata as m, json; print(json.dumps([{'name': d.metadata['Name'], 'version': d.version} for d in m.distributions()]))",
        ]
    } else {
        vec![
            "-m",
            "pip",
            "list",
            "--format=json",
            "--disable-pip-version-check",
        ]
    };
    let output = ProcessCommand::new(python_path)
        .args(args)
        .output()
        .map_err(|e| format!("failed to run `{}`: {e}", python_path.display()))?;

    if !output.status.success() {
        return Err(format!(
            "Package inventory using `{}` exited with {}: {}",
            python_path.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let raw: Vec<Value> = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("failed to parse package inventory output: {e}"))?;

    Ok(raw
        .into_iter()
        .map(|p| InstalledPackage {
            name: p
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string(),
            version: p
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        })
        .collect())
}

/// Query the OSV API for known vulnerabilities affecting `packages`, keeping
/// only vulnerabilities at or above `severity_threshold` (e.g. "low",
/// "medium", "high", "critical").
pub async fn scan_for_vulnerabilities(
    packages: &[InstalledPackage],
    osv_url: &str,
    severity_threshold: &str,
) -> Result<AuditReport, String> {
    let threshold_level = severity_level(severity_threshold);

    if packages.is_empty() {
        return Ok(AuditReport {
            scanned: 0,
            unscanned: 0,
            vulnerabilities: Vec::new(),
        });
    }

    let queries: Vec<Value> = packages
        .iter()
        .map(|p| {
            json!({
                "version": p.version,
                "package": {
                    "name": p.name,
                    "ecosystem": "PyPI"
                }
            })
        })
        .collect();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;

    let mut active: Vec<(usize, Value)> = queries.into_iter().enumerate().collect();
    let mut seen_tokens = vec![BTreeSet::new(); packages.len()];
    let mut package_ids = vec![BTreeSet::new(); packages.len()];
    let mut details = BTreeMap::new();
    let mut unscanned = BTreeSet::new();
    let mut vulnerabilities = Vec::new();
    let mut detail_base =
        reqwest::Url::parse(osv_url).map_err(|_| "Invalid OSV endpoint".to_string())?;
    detail_base.set_query(None);
    detail_base.set_fragment(None);
    detail_base
        .path_segments_mut()
        .map_err(|_| "Invalid OSV endpoint".to_string())?
        .pop()
        .push("vulns");

    while !active.is_empty() {
        let batch: Vec<&Value> = active.iter().map(|(_, query)| query).collect();
        let response = client
            .post(osv_url)
            .json(&json!({"queries": batch}))
            .send()
            .await
            .map_err(|_| "OSV batch request failed".to_string())?;
        if !response.status().is_success() {
            return Err(format!(
                "OSV API returned HTTP {}: scan results unavailable",
                response.status()
            ));
        }
        let data: Value = response
            .json()
            .await
            .map_err(|_| "Failed to parse OSV response".to_string())?;
        let results = data
            .get("results")
            .and_then(Value::as_array)
            .ok_or("OSV response is missing results")?;
        if results.len() > active.len() {
            return Err("OSV response contains excess package results".into());
        }
        for (index, _) in active.iter().skip(results.len()) {
            unscanned.insert(*index);
        }
        let mut next = Vec::new();
        for ((index, mut query), result) in active.into_iter().zip(results) {
            if !result.is_object() || result.get("error").is_some() {
                return Err("OSV returned an invalid package result".into());
            }
            if let Some(vulns) = result.get("vulns") {
                for stub in vulns.as_array().ok_or("Invalid OSV vulnerability list")? {
                    let id = stub
                        .get("id")
                        .and_then(Value::as_str)
                        .filter(|id| {
                            !id.is_empty()
                                && id
                                    .bytes()
                                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
                        })
                        .ok_or("OSV returned an invalid advisory ID")?;
                    if !package_ids[index].insert(id.to_string()) {
                        continue;
                    }
                    if !details.contains_key(id) {
                        let mut url = detail_base.clone();
                        url.path_segments_mut()
                            .map_err(|_| "Invalid OSV endpoint")?
                            .push(id);
                        let response = client
                            .get(url)
                            .send()
                            .await
                            .map_err(|_| format!("OSV advisory lookup failed for {id}"))?;
                        if !response.status().is_success() {
                            return Err(format!(
                                "OSV advisory lookup failed for {id}: HTTP {}",
                                response.status()
                            ));
                        }
                        let advisory: Value = response
                            .json()
                            .await
                            .map_err(|_| format!("Invalid OSV advisory response for {id}"))?;
                        if advisory.get("id").and_then(Value::as_str) != Some(id) {
                            return Err(format!("OSV advisory ID mismatch for {id}"));
                        }
                        details.insert(id.to_string(), advisory);
                    }
                    let advisory = &details[id];
                    let severity = extract_severity(advisory);
                    if severity_level(&severity) < threshold_level {
                        continue;
                    }
                    let pkg = &packages[index];
                    vulnerabilities.push(Vulnerability {
                        package: pkg.name.clone(),
                        installed_version: pkg.version.clone(),
                        vulnerability_id: id.to_string(),
                        severity,
                        description: advisory
                            .get("summary")
                            .or_else(|| advisory.get("details"))
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                        fix_version: extract_fix_version(advisory, &pkg.name),
                    });
                }
            }
            if let Some(token) = result.get("next_page_token") {
                let token = token.as_str().ok_or("Invalid OSV page token")?;
                if !token.is_empty() {
                    if !seen_tokens[index].insert(token.to_string()) {
                        return Err("OSV repeated a pagination token".into());
                    }
                    query["page_token"] = json!(token);
                    next.push((index, query));
                }
            }
        }
        active = next;
    }
    Ok(AuditReport {
        scanned: packages.len(),
        unscanned: unscanned.len(),
        vulnerabilities,
    })
}

/// Rank a severity string for threshold comparisons. Unknown strings are
/// ranked conservatively above critical so missing evidence cannot bypass a gate.
pub fn severity_level(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "none" => 0,
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => 5,
    }
}

/// Inverse of [`severity_level`]. Used to compute the more permissive of two
/// thresholds (e.g. `--severity-threshold` and `--fail-on`) as a string
/// suitable for [`scan_for_vulnerabilities`].
pub fn severity_str_for_level(level: u8) -> &'static str {
    match level {
        0 => "none",
        1 => "low",
        2 => "medium",
        3 => "high",
        _ => "critical",
    }
}

fn extract_severity(vuln: &Value) -> String {
    // Primary: database_specific.severity — present in GHSA-sourced advisories
    if let Some(db_sev) = vuln
        .get("database_specific")
        .and_then(|d| d.get("severity"))
        .and_then(|s| s.as_str())
    {
        return normalize_severity(db_sev);
    }

    // Fallback: OSV severity[] array with CVSS vectors — common in PYSEC advisories
    if let Some(severities) = vuln.get("severity").and_then(|s| s.as_array()) {
        for sev in severities {
            let score_str = sev.get("score").and_then(|s| s.as_str()).unwrap_or("");
            if let Some(level) = severity_from_cvss_vector(score_str) {
                return level;
            }
        }
    }

    "unknown".to_string()
}

fn normalize_severity(s: &str) -> String {
    match s.to_uppercase().as_str() {
        "CRITICAL" => "critical",
        "HIGH" => "high",
        "MEDIUM" | "MODERATE" => "medium",
        "LOW" => "low",
        _ => "unknown",
    }
    .to_string()
}

/// Extract severity from a CVSS v3 vector string.
///
/// CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
/// Heuristic: if any of C/I/A is H → HIGH; all N → MEDIUM; else LOW.
/// Scope:Changed or PR:N+UI:N escalates to CRITICAL when C:H.
fn severity_from_cvss_vector(vector: &str) -> Option<String> {
    // Only CVSS v3.x base metrics are interpreted below (AV/AC/PR/UI/S/C/I/A
    // with the specific values this heuristic expects). A bare "CVSS:"
    // prefix would also match CVSS v2 (no version segment) or a future v4.x
    // vector, whose metric names/values differ and would be misclassified by
    // this v3-specific logic.
    if !vector.starts_with("CVSS:3.0/") && !vector.starts_with("CVSS:3.1/") {
        return None;
    }

    // Match on the exact key before the ':' in each "/"-separated segment.
    // A prefix match (e.g. `starts_with("C")`) would incorrectly match the
    // leading "CVSS:3.1" segment itself when looking up key "C".
    let get = |key: &str| -> Option<&str> {
        vector.split('/').find_map(|part| {
            part.split_once(':')
                .filter(|(k, _)| *k == key)
                .map(|(_, v)| v)
        })
    };

    let confidentiality = get("C")?;
    let integrity = get("I")?;
    let availability = get("A")?;
    let scope = get("S");
    let pr = get("PR");
    let ui = get("UI");

    let any_high = [confidentiality, integrity, availability].contains(&"H");
    let all_none = confidentiality == "N" && integrity == "N" && availability == "N";

    let level = if any_high
        && confidentiality == "H"
        && scope == Some("C")
        && pr == Some("N")
        && ui == Some("N")
    {
        "critical"
    } else if any_high {
        "high"
    } else if all_none {
        "low"
    } else {
        "medium"
    };

    Some(level.to_string())
}

fn extract_fix_version(vuln: &Value, package: &str) -> Option<String> {
    let normalize = |name: &str| {
        name.to_ascii_lowercase()
            .split(['-', '_', '.'])
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join("-")
    };
    let package = normalize(package);
    // Look in affected[].ranges[].events[].fixed
    if let Some(affected) = vuln.get("affected").and_then(|a| a.as_array()) {
        for aff in affected {
            let matches_package = aff.get("package").is_some_and(|p| {
                p.get("ecosystem").and_then(Value::as_str) == Some("PyPI")
                    && p.get("name")
                        .and_then(Value::as_str)
                        .is_some_and(|name| normalize(name) == package)
            });
            if !matches_package {
                continue;
            }
            if let Some(ranges) = aff.get("ranges").and_then(|r| r.as_array()) {
                for range in ranges {
                    if let Some(events) = range.get("events").and_then(|e| e.as_array()) {
                        for event in events {
                            if let Some(fixed) = event.get("fixed").and_then(|f| f.as_str()) {
                                return Some(fixed.to_string());
                            }
                        }
                    }
                }
            }
        }
        if !affected.is_empty() {
            return None;
        }
    }

    // Fallback: database_specific.fix_versions
    vuln.get("database_specific")
        .and_then(|d| d.get("fix_versions"))
        .and_then(|f| f.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn inventory_supports_uv_environments_without_pip() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("uv.lock"), "version=1\n").unwrap();
        let status = std::process::Command::new("python3")
            .args(["-m", "venv", "--without-pip"])
            .arg(temp.path())
            .status()
            .unwrap();
        assert!(status.success());
        let packages = super::list_installed_packages(&temp.path().join("bin/python")).unwrap();
        assert!(packages.is_empty());
    }
    use super::*;

    #[tokio::test]
    async fn scan_hydrates_paginated_ids_and_preserves_package_association() {
        use httpmock::prelude::*;
        let server = MockServer::start();
        let first = server.mock(|when, then| {
            when.method(POST)
                .path("/v1/querybatch")
                .body_excludes("page_token");
            then.status(200).json_body(json!({"results": [
                {"vulns": [{"id": "GHSA-shared"}]},
                {"vulns": [{"id": "GHSA-shared"}], "next_page_token": "next"}
            ]}));
        });
        let next = server.mock(|when, then| {
            when.method(POST).path("/v1/querybatch")
                .json_body(json!({"queries": [{"package": {"name": "beta", "ecosystem": "PyPI"}, "version": "2", "page_token": "next"}]}));
            then.status(200).json_body(json!({"results": [{"vulns": [{"id": "GHSA-critical"}, {"id": "GHSA-shared"}]}]}));
        });
        let shared = server.mock(|when, then| {
            when.method(GET).path("/v1/vulns/GHSA-shared");
            then.status(200).json_body(json!({"id": "GHSA-shared", "summary": "shared advisory", "database_specific": {"severity": "HIGH"}, "affected": []}));
        });
        let critical = server.mock(|when, then| {
            when.method(GET).path("/v1/vulns/GHSA-critical");
            then.status(200).json_body(json!({"id": "GHSA-critical", "summary": "critical advisory", "database_specific": {"severity": "CRITICAL"}, "affected": []}));
        });
        let packages = vec![
            InstalledPackage {
                name: "alpha".into(),
                version: "1".into(),
            },
            InstalledPackage {
                name: "beta".into(),
                version: "2".into(),
            },
        ];
        let report = scan_for_vulnerabilities(
            &packages,
            &format!("{}/v1/querybatch", server.base_url()),
            "high",
        )
        .await
        .unwrap();
        assert_eq!(report.vulnerabilities.len(), 3);
        assert_eq!(report.count_at_severity("high"), 2);
        assert_eq!(report.count_at_severity("critical"), 1);
        assert!(
            report
                .vulnerabilities
                .iter()
                .any(|v| v.package == "beta" && v.vulnerability_id == "GHSA-shared")
        );
        first.assert_calls(1);
        next.assert_calls(1);
        shared.assert_calls(1);
        critical.assert_calls(1);
    }

    #[tokio::test]
    async fn scan_never_reports_detail_failure_as_low_risk() {
        use httpmock::prelude::*;
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/v1/querybatch");
            then.status(200)
                .json_body(json!({"results": [{"vulns": [{"id": "GHSA-missing"}]}]}));
        });
        let result = scan_for_vulnerabilities(
            &[InstalledPackage {
                name: "alpha".into(),
                version: "1".into(),
            }],
            &format!("{}/v1/querybatch", server.base_url()),
            "high",
        )
        .await;
        assert!(result.is_err(), "missing details must fail the scan");
    }

    #[tokio::test]
    async fn scan_keeps_unknown_severity_above_every_threshold() {
        use httpmock::prelude::*;
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/v1/querybatch");
            then.status(200)
                .json_body(json!({"results": [{"vulns": [{"id": "GHSA-unknown"}]}]}));
        });
        server.mock(|when, then| {
            when.method(GET).path("/v1/vulns/GHSA-unknown");
            then.status(200).json_body(
                json!({"id": "GHSA-unknown", "summary": "No severity evidence", "affected": []}),
            );
        });
        let report = scan_for_vulnerabilities(
            &[InstalledPackage {
                name: "alpha".into(),
                version: "1".into(),
            }],
            &format!("{}/v1/querybatch", server.base_url()),
            "critical",
        )
        .await
        .unwrap();
        assert_eq!(report.vulnerabilities.len(), 1);
        assert_eq!(report.vulnerabilities[0].severity, "unknown");
    }

    #[test]
    fn fixes_follow_the_queried_package_in_shared_advisories() {
        let advisory = json!({"affected": [
            {"package": {"ecosystem": "PyPI", "name": "alpha"}, "ranges": [{"events": [{"fixed": "2"}]}]},
            {"package": {"ecosystem": "PyPI", "name": "Beta_pkg"}, "ranges": [{"events": [{"fixed": "9"}]}]}
        ]});
        assert_eq!(extract_fix_version(&advisory, "beta-pkg"), Some("9".into()));
        assert_eq!(extract_fix_version(&advisory, "alpha"), Some("2".into()));
        assert_eq!(extract_fix_version(&advisory, "other"), None);
    }

    #[tokio::test]
    async fn scan_rejects_invalid_details_and_pagination_loops() {
        use httpmock::prelude::*;
        for mode in ["id_mismatch", "invalid_json", "repeated_token"] {
            let server = MockServer::start();
            server.mock(|when, then| {
                when.method(POST).path("/v1/querybatch");
                let mut result = json!({"vulns": [{"id": "GHSA-test"}]});
                if mode == "repeated_token" {
                    result["next_page_token"] = json!("same");
                }
                then.status(200).json_body(json!({"results": [result]}));
            });
            server.mock(|when, then| {
                when.method(GET).path("/v1/vulns/GHSA-test");
                if mode == "invalid_json" {
                    then.status(200).body("not json");
                } else {
                    then.status(200).json_body(
                        json!({"id": if mode == "id_mismatch" {"GHSA-other"} else {"GHSA-test"}}),
                    );
                }
            });
            let result = scan_for_vulnerabilities(
                &[InstalledPackage {
                    name: "demo".into(),
                    version: "1".into(),
                }],
                &format!("{}/v1/querybatch", server.base_url()),
                "high",
            )
            .await;
            assert!(result.is_err(), "must reject {mode}");
        }
    }

    #[test]
    fn severity_level_orders_known_levels() {
        assert_eq!(severity_level("none"), 0);
        assert_eq!(severity_level("low"), 1);
        assert_eq!(severity_level("medium"), 2);
        assert_eq!(severity_level("high"), 3);
        assert_eq!(severity_level("critical"), 4);
    }

    #[test]
    fn severity_level_is_case_insensitive_and_ranks_unknown_conservatively() {
        assert_eq!(severity_level("HIGH"), 3);
        assert_eq!(severity_level("totally-unknown"), 5);
    }

    #[test]
    fn extract_severity_prefers_database_specific() {
        let vuln = json!({"database_specific": {"severity": "HIGH"}});
        assert_eq!(extract_severity(&vuln), "high");
    }

    #[test]
    fn extract_severity_falls_back_to_cvss_vector() {
        let vuln = json!({
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]
        });
        assert_eq!(extract_severity(&vuln), "high");
    }

    #[test]
    fn extract_severity_falls_back_to_cvss_vector_regardless_of_metric_order() {
        // Same metrics as above, reordered — the exact-key lookup must not
        // depend on segment position.
        let vuln = json!({
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/C:H/I:N/A:N/AV:N/AC:L/PR:N/UI:N/S:U"}]
        });
        assert_eq!(extract_severity(&vuln), "high");
    }

    #[test]
    fn extract_severity_ignores_cvss_v2_vectors() {
        // CVSS v2 has no version segment and different metric semantics; a
        // bare "CVSS:" prefix check would misclassify this using v3 rules.
        let vuln = json!({
            "severity": [{"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:C/I:C/A:C"}]
        });
        assert_eq!(extract_severity(&vuln), "unknown");
    }

    #[test]
    fn extract_severity_ignores_malformed_cvss_header() {
        let vuln = json!({
            "severity": [{"type": "CVSS_V3", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"}]
        });
        assert_eq!(extract_severity(&vuln), "unknown");
    }

    #[test]
    fn extract_severity_reports_unknown_when_no_data() {
        let vuln = json!({});
        assert_eq!(extract_severity(&vuln), "unknown");
    }

    #[test]
    fn extract_fix_version_reads_affected_ranges() {
        let vuln = json!({
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "ranges": [{
                    "events": [{"introduced": "0"}, {"fixed": "2.31.0"}]
                }]
            }]
        });
        assert_eq!(
            extract_fix_version(&vuln, "requests"),
            Some("2.31.0".to_string())
        );
    }

    #[test]
    fn extract_fix_version_falls_back_to_database_specific() {
        let vuln = json!({
            "database_specific": {"fix_versions": ["1.2.3"]}
        });
        assert_eq!(
            extract_fix_version(&vuln, "requests"),
            Some("1.2.3".to_string())
        );
    }

    #[test]
    fn extract_fix_version_returns_none_when_absent() {
        let vuln = json!({});
        assert_eq!(extract_fix_version(&vuln, "requests"), None);
    }

    #[tokio::test]
    async fn scan_for_vulnerabilities_returns_empty_report_for_no_packages() {
        let report = scan_for_vulnerabilities(&[], "http://127.0.0.1:1/unused", "low")
            .await
            .unwrap();
        assert_eq!(report.scanned, 0);
        assert_eq!(report.unscanned, 0);
        assert!(report.vulnerabilities.is_empty());
    }

    #[test]
    fn list_installed_packages_returns_err_when_python_binary_missing() {
        // A path that doesn't exist should surface as an error, not silently
        // become "zero packages" — CI callers (`pybun audit --fail-on`) rely
        // on distinguishing "scanned, found nothing" from "couldn't scan".
        let result =
            list_installed_packages(Path::new("/nonexistent/path/to/python-does-not-exist"));
        assert!(result.is_err());
    }

    #[test]
    fn severity_str_for_level_round_trips_with_severity_level() {
        for s in ["none", "low", "medium", "high", "critical"] {
            assert_eq!(severity_str_for_level(severity_level(s)), s);
        }
    }

    #[test]
    fn count_at_severity_counts_matching_entries() {
        let report = AuditReport {
            scanned: 2,
            unscanned: 0,
            vulnerabilities: vec![
                Vulnerability {
                    package: "a".into(),
                    installed_version: "1".into(),
                    vulnerability_id: "V1".into(),
                    severity: "high".into(),
                    description: String::new(),
                    fix_version: None,
                },
                Vulnerability {
                    package: "b".into(),
                    installed_version: "1".into(),
                    vulnerability_id: "V2".into(),
                    severity: "low".into(),
                    description: String::new(),
                    fix_version: None,
                },
            ],
        };
        assert_eq!(report.count_at_severity("high"), 1);
        assert_eq!(report.count_at_severity("low"), 1);
        assert_eq!(report.count_at_severity("critical"), 0);
        assert_eq!(report.highest_severity_level(), Some(3));
    }
}
