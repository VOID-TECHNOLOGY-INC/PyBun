//! Shared OSV-based vulnerability scanning primitives.
//!
//! Used by both the MCP `pybun_audit` tool (`src/mcp.rs`) and the CLI
//! `pybun audit` command (`src/commands/maintenance.rs`) so the two surfaces
//! query the same OSV endpoint, apply the same severity normalization, and
//! report the same counts (Issue #316, in the spirit of the PR-A3 MCP/CLI
//! unification goal).

use serde_json::{Value, json};
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

/// List installed packages in the given Python environment via
/// `pip list --format=json`. Returns an empty list (rather than erroring) if
/// pip is unavailable or the invocation fails, so callers can treat "nothing
/// to scan" uniformly.
pub fn list_installed_packages(python_path: &Path) -> Vec<InstalledPackage> {
    let output = ProcessCommand::new(python_path)
        .args([
            "-m",
            "pip",
            "list",
            "--format=json",
            "--disable-pip-version-check",
        ])
        .output()
        .ok();

    let raw: Vec<Value> = output
        .filter(|o| o.status.success())
        .and_then(|o| serde_json::from_slice(&o.stdout).ok())
        .unwrap_or_default();

    raw.into_iter()
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
        .collect()
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

    let response = client
        .post(osv_url)
        .json(&json!({"queries": queries}))
        .send()
        .await
        .map_err(|e| format!("OSV API request failed: {}", e))?;

    let status = response.status();
    if !status.is_success() {
        return Err(format!(
            "OSV API returned HTTP {}: scan results unavailable",
            status
        ));
    }

    let osv_data: Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse OSV response: {}", e))?;

    // Process OSV results — one result entry per queried package (same order).
    // Per OSV spec, results.len() == queries.len(); we use zip so mismatches
    // (e.g., partial error responses or mock servers) are handled gracefully.
    let empty_vec = vec![];
    let results = osv_data
        .get("results")
        .and_then(|r| r.as_array())
        .unwrap_or(&empty_vec);

    let unscanned = packages.len().saturating_sub(results.len());

    let mut vulnerabilities: Vec<Vulnerability> = Vec::new();

    for (pkg, result) in packages.iter().zip(results.iter()) {
        let empty_vulns = vec![];
        let vulns = result
            .get("vulns")
            .and_then(|v| v.as_array())
            .unwrap_or(&empty_vulns);

        for vuln in vulns {
            let severity = extract_severity(vuln);
            if severity_level(&severity) < threshold_level {
                continue;
            }

            let vulnerability_id = vuln
                .get("id")
                .and_then(|i| i.as_str())
                .unwrap_or("")
                .to_string();
            let description = vuln
                .get("summary")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string();

            vulnerabilities.push(Vulnerability {
                package: pkg.name.clone(),
                installed_version: pkg.version.clone(),
                vulnerability_id,
                severity,
                description,
                fix_version: extract_fix_version(vuln),
            });
        }
    }

    Ok(AuditReport {
        scanned: packages.len(),
        unscanned,
        vulnerabilities,
    })
}

/// Rank a severity string for threshold comparisons. Unknown strings are
/// treated as "low" (fail-open on ranking, not on reporting).
pub fn severity_level(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "none" => 0,
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => 1,
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

    "low".to_string()
}

fn normalize_severity(s: &str) -> String {
    match s.to_uppercase().as_str() {
        "CRITICAL" => "critical",
        "HIGH" => "high",
        "MEDIUM" | "MODERATE" => "medium",
        "LOW" => "low",
        _ => "low",
    }
    .to_string()
}

/// Extract severity from a CVSS v3 vector string.
///
/// CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
/// Heuristic: if any of C/I/A is H → HIGH; all N → MEDIUM; else LOW.
/// Scope:Changed or PR:N+UI:N escalates to CRITICAL when C:H.
fn severity_from_cvss_vector(vector: &str) -> Option<String> {
    if !vector.starts_with("CVSS:") {
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

fn extract_fix_version(vuln: &Value) -> Option<String> {
    // Look in affected[].ranges[].events[].fixed
    if let Some(affected) = vuln.get("affected").and_then(|a| a.as_array()) {
        for aff in affected {
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
    use super::*;

    #[test]
    fn severity_level_orders_known_levels() {
        assert_eq!(severity_level("none"), 0);
        assert_eq!(severity_level("low"), 1);
        assert_eq!(severity_level("medium"), 2);
        assert_eq!(severity_level("high"), 3);
        assert_eq!(severity_level("critical"), 4);
    }

    #[test]
    fn severity_level_is_case_insensitive_and_defaults_unknown_to_low() {
        assert_eq!(severity_level("HIGH"), 3);
        assert_eq!(severity_level("totally-unknown"), 1);
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
    fn extract_severity_defaults_to_low_when_no_data() {
        let vuln = json!({});
        assert_eq!(extract_severity(&vuln), "low");
    }

    #[test]
    fn extract_fix_version_reads_affected_ranges() {
        let vuln = json!({
            "affected": [{
                "ranges": [{
                    "events": [{"introduced": "0"}, {"fixed": "2.31.0"}]
                }]
            }]
        });
        assert_eq!(extract_fix_version(&vuln), Some("2.31.0".to_string()));
    }

    #[test]
    fn extract_fix_version_falls_back_to_database_specific() {
        let vuln = json!({
            "database_specific": {"fix_versions": ["1.2.3"]}
        });
        assert_eq!(extract_fix_version(&vuln), Some("1.2.3".to_string()));
    }

    #[test]
    fn extract_fix_version_returns_none_when_absent() {
        let vuln = json!({});
        assert_eq!(extract_fix_version(&vuln), None);
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
