//! Operator-owned source equivalence and disclosure decisions.

use super::model::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceRule {
    pub name: String,
    pub distribution: Option<String>,
    pub source_id: String,
    pub upstream_name: Option<String>,
    pub ecosystem: Option<String>,
    pub assumption: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DisclosureGrant {
    pub provider_id: String,
    pub source_id: String,
    pub packages: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct SourcePolicy {
    pub sources: Vec<SourceIdentity>,
    pub rules: Vec<SourceRule>,
    pub disclosure: Vec<DisclosureGrant>,
}

/// A query may only be constructed after both independent policy decisions.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AuthorizedQuery {
    pub(crate) provider_id: String,
    pub(crate) source_id: String,
    pub(crate) auth_scope_id: String,
    pub(crate) ecosystem: String,
    pub(crate) name: String,
    pub(crate) assumption: String,
}

impl AuthorizedQuery {
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }
    pub fn source_id(&self) -> &str {
        &self.source_id
    }
    pub fn auth_scope_id(&self) -> &str {
        &self.auth_scope_id
    }
    pub fn ecosystem(&self) -> &str {
        &self.ecosystem
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn assumption(&self) -> &str {
        &self.assumption
    }
}

impl SourceIdentity {
    pub fn new(
        id: &str,
        auth_scope_id: &str,
        kind: SourceKind,
    ) -> Result<Self, ObservationDiagnostic> {
        if !opaque_id(id) || !opaque_id(auth_scope_id) {
            return Err(ObservationDiagnostic::new(
                "E_SECURITY_SOURCE_POLICY",
                "Source and authorization-scope identities must be opaque identifiers, not URLs or credentials.",
            ));
        }
        Ok(Self {
            id: id.into(),
            auth_scope_id: auth_scope_id.into(),
            kind,
        })
    }
}

pub fn normalize_name(name: &str) -> Result<String, ObservationDiagnostic> {
    if name.is_empty()
        || name.len() > 200
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name.as_bytes()[name.len() - 1].is_ascii_alphanumeric()
    {
        return Err(ObservationDiagnostic::new(
            "E_SECURITY_METADATA",
            "Package metadata has an invalid package name.",
        ));
    }
    let mut result = String::new();
    for c in name.bytes() {
        if matches!(c, b'.' | b'_' | b'-') {
            if !result.ends_with('-') {
                result.push('-');
            }
        } else {
            result.push((c as char).to_ascii_lowercase());
        }
    }
    Ok(result)
}

pub(crate) fn opaque_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
}

impl SourcePolicy {
    pub fn validate(&self) -> Result<(), ObservationDiagnostic> {
        let mut ids = std::collections::BTreeSet::new();
        for source in &self.sources {
            SourceIdentity::new(&source.id, &source.auth_scope_id, source.kind)?;
            if !ids.insert(&source.id) {
                return Err(policy_error());
            }
        }
        for rule in &self.rules {
            normalize_name(&rule.name)?;
            if !ids.contains(&rule.source_id) {
                return Err(policy_error());
            }
            let mapped = rule.upstream_name.is_some()
                || rule.ecosystem.is_some()
                || rule.assumption.is_some();
            if mapped
                && (rule.upstream_name.is_none()
                    || rule.ecosystem.as_deref() != Some("PyPI")
                    || rule
                        .assumption
                        .as_ref()
                        .is_none_or(|s| s.trim().is_empty() || s.len() > 1024))
            {
                return Err(policy_error());
            }
            if let Some(name) = &rule.upstream_name {
                normalize_name(name)?;
            }
            if rule
                .distribution
                .as_ref()
                .is_some_and(|s| s.is_empty() || s.contains(['/', '\\']) || s == "." || s == "..")
            {
                return Err(policy_error());
            }
        }
        for grant in &self.disclosure {
            if !opaque_id(&grant.provider_id) || !ids.contains(&grant.source_id) {
                return Err(policy_error());
            }
            for name in &grant.packages {
                normalize_name(name)?;
            }
        }
        Ok(())
    }

    pub fn map_package(
        &self,
        name: &str,
        distribution: &str,
        detected_kind: SourceKind,
    ) -> Result<PackageSource, ObservationDiagnostic> {
        self.map_package_with_origin(name, distribution, detected_kind, None)
    }

    pub fn map_package_with_origin(
        &self,
        name: &str,
        distribution: &str,
        detected_kind: SourceKind,
        origin_identity: Option<&str>,
    ) -> Result<PackageSource, ObservationDiagnostic> {
        self.validate()?;
        if distribution.is_empty()
            || distribution.contains(['/', '\\'])
            || origin_identity.is_some_and(|id| !opaque_id(id))
        {
            return Err(policy_error());
        }
        let name = normalize_name(name)?;
        let matching: Vec<_> = self
            .rules
            .iter()
            .filter(|r| {
                normalize_name(&r.name).ok().as_deref() == Some(&name)
                    && r.distribution.as_deref().is_none_or(|d| d == distribution)
            })
            .collect();
        let specific: Vec<_> = matching
            .iter()
            .copied()
            .filter(|r| r.distribution.is_some())
            .collect();
        let matching = if specific.is_empty() {
            matching
        } else {
            specific
        };
        if matching.len() > 1 {
            return Err(policy_error());
        }
        // A public-name assumption never erases explicit direct/VCS/editable origin.
        if !matches!(
            detected_kind,
            SourceKind::Unknown | SourceKind::PublicRegistry | SourceKind::PrivateRegistry
        ) {
            return Ok(unknown_source(
                &name,
                distribution,
                detected_kind,
                origin_identity,
            ));
        }
        let Some(rule) = matching.first() else {
            return Ok(unknown_source(
                &name,
                distribution,
                detected_kind,
                origin_identity,
            ));
        };
        let source = self
            .sources
            .iter()
            .find(|s| s.id == rule.source_id)
            .ok_or_else(policy_error)?
            .clone();
        let mapping = match (&rule.upstream_name, &rule.ecosystem, &rule.assumption) {
            (Some(upstream), Some(ecosystem), Some(assumption)) => Some(SourceMapping {
                ecosystem: ecosystem.clone(),
                upstream_name: normalize_name(upstream)?,
                assumption: crate::support_bundle::redact_text(assumption),
            }),
            _ => None,
        };
        Ok(PackageSource {
            source,
            mapping,
            distribution: distribution.into(),
            origin_identity: origin_identity.map(str::to_owned),
        })
    }

    pub fn may_disclose(&self, provider_id: &str, source_id: &str, name: &str) -> bool {
        let Ok(name) = normalize_name(name) else {
            return false;
        };
        self.disclosure.iter().any(|g| {
            g.provider_id == provider_id
                && g.source_id == source_id
                && g.packages
                    .iter()
                    .any(|n| normalize_name(n).ok().as_ref() == Some(&name))
        })
    }

    pub fn authorized_query(
        &self,
        provider_id: &str,
        name: &str,
        source: &PackageSource,
    ) -> Result<AuthorizedQuery, ObservationDiagnostic> {
        self.validate()?;
        let Some(mapping) = &source.mapping else {
            return Err(ObservationDiagnostic::new(
                "E_SECURITY_SOURCE_MAPPING_UNKNOWN",
                "No approved upstream mapping is available for this package instance.",
            ));
        };
        if !self.may_disclose(provider_id, &source.source.id, name) {
            return Err(ObservationDiagnostic::new(
                "E_SECURITY_DISCLOSURE_DENIED",
                "Package identity disclosure to this provider is not authorized.",
            ));
        }
        let name = normalize_name(name)?;
        let current = self.map_package_with_origin(
            &name,
            &source.distribution,
            source.source.kind,
            source.origin_identity.as_deref(),
        )?;
        if &current != source {
            return Err(policy_error());
        }
        Ok(AuthorizedQuery {
            provider_id: provider_id.into(),
            source_id: source.source.id.clone(),
            auth_scope_id: source.source.auth_scope_id.clone(),
            ecosystem: mapping.ecosystem.clone(),
            name: mapping.upstream_name.clone(),
            assumption: mapping.assumption.clone(),
        })
    }
}

fn unknown_source(
    name: &str,
    distribution: &str,
    kind: SourceKind,
    origin_identity: Option<&str>,
) -> PackageSource {
    PackageSource {
        distribution: distribution.into(),
        origin_identity: origin_identity.map(str::to_owned),
        source: SourceIdentity {
            id: format!(
                "unknown-{}",
                semantic_digest(&(name, distribution, kind, origin_identity))
            ),
            auth_scope_id: "none".into(),
            kind,
        },
        mapping: None,
    }
}

fn policy_error() -> ObservationDiagnostic {
    ObservationDiagnostic::new(
        "E_SECURITY_SOURCE_POLICY",
        "Source policy is invalid or ambiguous.",
    )
}
