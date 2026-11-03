//! Registry disclosure uses installed distribution identity, independently of
//! the upstream identity used by advisory providers.

use super::registry::{RegistryCatalog, parse_registry_catalog};
use crate::security_assessment::http::{HttpSession, ProviderConfig, ProviderEndpoint};
use crate::security_assessment::source::{AuthorizedQuery, opaque_id};
use crate::security_assessment::{
    CoverageStatus, ObservationDiagnostic, PackageInstance, SourceKind, SourcePolicy,
    TargetTagProfile, normalize_name,
};
use reqwest::{Method, Url};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySourceConfig {
    pub source_id: String,
    pub provider: ProviderConfig,
}

#[derive(Debug, Clone)]
pub struct RegistrySource {
    source_id: String,
    endpoint: ProviderEndpoint,
}

/// Constructed only after current source binding and disclosure checks. It
/// cannot be deserialized or supplied by a transport client as authorization.
pub(crate) struct AuthorizedRegistryQuery {
    pub distribution: String,
    pub url: Url,
    pub transport: AuthorizedQuery,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryObservation {
    pub freshness: crate::security_assessment::http::EvidenceFreshness,
    pub source_id: String,
    pub source_auth_scope_id: String,
    pub provider_id: String,
    pub provider_auth_scope_id: String,
    pub distribution: String,
    pub fetched_at: u64,
    pub payload_digest: String,
    pub catalog: RegistryCatalog,
}

impl RegistrySource {
    pub fn new(config: RegistrySourceConfig) -> Result<Self, ObservationDiagnostic> {
        if !opaque_id(&config.source_id) {
            return Err(source_error());
        }
        let endpoint = ProviderEndpoint::new(config.provider)?;
        if !endpoint.url().path().ends_with('/') {
            return Err(source_error());
        }
        Ok(Self {
            source_id: config.source_id,
            endpoint,
        })
    }

    pub fn source_id(&self) -> &str {
        &self.source_id
    }
    pub fn provider(&self) -> &ProviderEndpoint {
        &self.endpoint
    }

    pub fn with_bearer_token(mut self, token: &str) -> Result<Self, ObservationDiagnostic> {
        self.endpoint = self.endpoint.with_bearer_token(token)?;
        Ok(self)
    }

    pub(crate) fn authorize(
        &self,
        package: &PackageInstance,
        policy: &SourcePolicy,
    ) -> Result<AuthorizedRegistryQuery, ObservationDiagnostic> {
        policy.validate()?;
        let original = package.package_source();
        let current = policy.map_package_with_origin(
            &package.name,
            &original.distribution,
            package.source.kind,
            package.origin_identity.as_deref(),
        )?;
        if current != original
            || current.source.id != self.source_id
            || !matches!(
                current.source.kind,
                SourceKind::PublicRegistry | SourceKind::PrivateRegistry
            )
            || package.coverage.status != CoverageStatus::Complete
        {
            return Err(source_error());
        }
        let distribution = normalize_name(&package.name)?;
        if !policy.may_disclose(self.endpoint.id(), &current.source.id, &distribution) {
            return Err(ObservationDiagnostic::new(
                "E_SECURITY_DISCLOSURE_DENIED",
                "Current policy does not permit submitting this distribution identity to the approved registry.",
            ));
        }
        let url = self
            .endpoint
            .url()
            .join(&format!("{distribution}/"))
            .map_err(|_| source_error())?;
        if !self.endpoint.permits(&url) {
            return Err(source_error());
        }
        // The HTTP proof is scoped to the registry namespace. It deliberately
        // uses the installed name, not SourceMapping.upstream_name.
        let transport = AuthorizedQuery {
            provider_id: self.endpoint.id().into(),
            source_id: current.source.id,
            auth_scope_id: current.source.auth_scope_id,
            ecosystem: "PyPI".into(),
            name: distribution.clone(),
            assumption: "Operator binds this distribution to the configured registry source."
                .into(),
        };
        Ok(AuthorizedRegistryQuery {
            distribution,
            url,
            transport,
        })
    }
}

pub async fn observe_registry(
    session: &HttpSession,
    source: &RegistrySource,
    package: &PackageInstance,
    target: &TargetTagProfile,
    policy: &SourcePolicy,
) -> Result<RegistryObservation, ObservationDiagnostic> {
    let query = source.authorize(package, policy)?;
    session.reserve_provider_page(source.endpoint.id())?;
    let evidence = session
        .request_json(
            &source.endpoint,
            Method::GET,
            query.url,
            None,
            &query.transport,
        )
        .await?;
    let catalog = parse_registry_catalog(&query.distribution, &evidence.value, target);
    session.remaining()?;
    let observed = RegistryObservation {
        freshness: evidence.freshness,
        source_id: query.transport.source_id,
        source_auth_scope_id: query.transport.auth_scope_id,
        provider_id: source.endpoint.id().into(),
        provider_auth_scope_id: source.endpoint.config().auth_scope_id.clone(),
        distribution: query.distribution,
        fetched_at: evidence.fetched_at,
        payload_digest: evidence.payload_digest,
        catalog,
    };
    let retained_size = serde_json::to_vec(&observed)
        .map_err(|_| source_error())?
        .len();
    session.remaining()?;
    session.reserve_evidence(retained_size)?;
    Ok(observed)
}

fn source_error() -> ObservationDiagnostic {
    ObservationDiagnostic::new(
        "E_SECURITY_REGISTRY_SOURCE",
        "Registry source identity, current distribution evidence, or approved endpoint binding is missing or changed; no request was authorized.",
    )
}
