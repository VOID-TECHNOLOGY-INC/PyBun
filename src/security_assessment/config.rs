//! Frozen operator grants for read-only checks. Transport requests cannot create
//! these grants or choose executable, endpoint, disclosure, or cache identities.
use super::{
    InventoryBackend, InventoryRequest, InventoryScope, InventoryTarget, ObservationDiagnostic,
    ObservationLimits, SourcePolicy,
    check::{CheckMode, CheckSeverityThreshold, CheckTarget, CheckUpdatesRequest},
    http::{ObservationMode, ProviderConfig, ProviderEndpoint},
    qualification::{
        provenance::{ApprovedRegistryBinding, ProvenanceRequest},
        registry_source::{RegistrySource, RegistrySourceConfig},
        schedule::AssessmentContinuation,
    },
    semantic_digest,
    source::opaque_id,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{Metadata, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

const CONFIG_BYTES: usize = 256 * 1024;
const EXECUTABLE_BYTES: u64 = 128 * 1024 * 1024;
const OUTPUT_BYTES: usize = 5 * 1024 * 1024;

/// Immutable operator authority; credentials intentionally have no serialization
/// or debug representation. Construct once at operator startup.
pub struct SecurityAuthority {
    default_profile: Option<String>,
    profiles: BTreeMap<String, Arc<FrozenProfile>>,
}

#[derive(Clone)]
pub struct ProfilePermissions {
    pub id: String,
    pub project_root: PathBuf,
    pub environment_root: PathBuf,
    pub backend: InventoryBackend,
    pub cache_root: Option<PathBuf>,
}

/// Only successful current authorization constructs the service input.
pub struct AuthorizedCheck {
    pub(crate) deadline: Instant,
    pub(crate) inventory: InventoryRequest,
    pub(crate) providers: Vec<ProviderEndpoint>,
    pub(crate) sources: Vec<RegistrySource>,
    pub(crate) mode: ObservationMode,
    pub(crate) cache_root: Option<PathBuf>,
    pub(crate) max_cache_age_seconds: u64,
    pub(crate) include_prereleases: bool,
    pub(crate) continuation: Option<AssessmentContinuation>,
    pub(crate) fail_on: Option<CheckSeverityThreshold>,
    pub(crate) profile_id: String,
    pub(crate) policy_digest: String,
    pub(crate) max_output_bytes: usize,
    pub(crate) provenance: Option<(ProvenanceRequest, Vec<ApprovedRegistryBinding>)>,
}
impl AuthorizedCheck {
    pub fn permissions(&self) -> ProfilePermissions {
        ProfilePermissions {
            id: self.profile_id.clone(),
            project_root: self.inventory.project_root.clone(),
            environment_root: self
                .inventory
                .environment
                .clone()
                .expect("authorized explicit environment"),
            backend: self.inventory.backend,
            cache_root: self.cache_root.clone(),
        }
    }
    pub fn limits(&self) -> &ObservationLimits {
        &self.inventory.limits
    }
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Section {
    config_version: u32,
    #[serde(default)]
    default_profile: Option<String>,
    #[serde(default)]
    profiles: Vec<Profile>,
    #[serde(default)]
    providers: Vec<Endpoint>,
    #[serde(default)]
    registries: Vec<Registry>,
    #[serde(default)]
    source_policies: BTreeMap<String, SourcePolicy>,
    #[serde(default)]
    limits: BTreeMap<String, u64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    id: String,
    project_root: PathBuf,
    environment: PathBuf,
    #[serde(default)]
    target: CheckTarget,
    backend: InventoryBackend,
    trusted_python: PathBuf,
    source_policy_id: String,
    #[serde(default)]
    provider_ids: Vec<String>,
    #[serde(default)]
    registry_source_ids: Vec<String>,
    #[serde(default)]
    cache_root: Option<PathBuf>,
    #[serde(default = "online_modes")]
    allowed_modes: Vec<CheckMode>,
    #[serde(default = "default_cache_age")]
    max_cache_age_seconds: u64,
    #[serde(default)]
    include_prereleases: bool,
    #[serde(default)]
    scope: InventoryScope,
    #[serde(default)]
    limits: BTreeMap<String, u64>,
    #[serde(default)]
    trusted_uv: Option<PathBuf>,
    #[serde(default)]
    provenance_cache_root: Option<PathBuf>,
    #[serde(default)]
    registry_bindings: Vec<ApprovedRegistryBinding>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Endpoint {
    id: String,
    url: String,
    auth_scope_id: String,
    #[serde(default)]
    allow_insecure_loopback: bool,
    #[serde(default)]
    bearer_token_env: Option<String>,
}
impl Endpoint {
    fn config(&self) -> ProviderConfig {
        ProviderConfig {
            id: self.id.clone(),
            url: self.url.clone(),
            auth_scope_id: self.auth_scope_id.clone(),
            allow_insecure_loopback: self.allow_insecure_loopback,
        }
    }
    fn endpoint(
        &self,
        credentials: &BTreeMap<String, String>,
    ) -> Result<ProviderEndpoint, ObservationDiagnostic> {
        let endpoint = ProviderEndpoint::new(self.config())?;
        match &self.bearer_token_env {
            Some(name) => {
                endpoint.with_bearer_token(credentials.get(name).ok_or_else(authority_error)?)
            }
            None => Ok(endpoint),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    source_id: String,
    provider: Endpoint,
}
struct FrozenProfile {
    permissions: ProfilePermissions,
    policy_digest: String,
    project: PinnedPath,
    environment: PinnedPath,
    python: PinnedPath,
    cache: Option<PinnedPath>,
    target: CheckTarget,
    policy: SourcePolicy,
    providers: Vec<ProviderEndpoint>,
    sources: Vec<RegistrySource>,
    allowed_modes: Vec<CheckMode>,
    limits: ObservationLimits,
    max_output_bytes: usize,
    max_cache_age_seconds: u64,
    include_prereleases: bool,
    scope: InventoryScope,
    provenance: Option<(PinnedPath, PinnedPath, Vec<ApprovedRegistryBinding>)>,
}

impl SecurityAuthority {
    /// Read one explicitly selected regular file, without following its final
    /// symlink or blocking on special files. Missing sections grant nothing.
    pub fn load(path: &Path) -> Result<Self, ObservationDiagnostic> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        if !cfg!(unix) {
            return Err(authority_error());
        }
        let mut file = options.open(path).map_err(|_| authority_error())?;
        let metadata = file.metadata().map_err(|_| authority_error())?;
        if !metadata.is_file() || metadata.len() > CONFIG_BYTES as u64 {
            return Err(authority_error());
        }
        let mut text = String::new();
        file.by_ref()
            .take(CONFIG_BYTES as u64 + 1)
            .read_to_string(&mut text)
            .map_err(|_| authority_error())?;
        let after = file.metadata().map_err(|_| authority_error())?;
        let current = std::fs::symlink_metadata(path).map_err(|_| authority_error())?;
        if text.len() > CONFIG_BYTES
            || current.file_type().is_symlink()
            || FileIdentity::from(&metadata) != FileIdentity::from(&current)
            || metadata.len() != after.len()
            || metadata.modified().ok() != after.modified().ok()
        {
            return Err(authority_error());
        }
        let base = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        Self::from_toml(&text, base)
    }

    /// Freeze operator configuration and resolve credential references once.
    /// Errors never include parser input, paths, endpoint URLs, or secret values.
    pub fn from_toml(text: &str, base: &Path) -> Result<Self, ObservationDiagnostic> {
        if text.len() > CONFIG_BYTES {
            return Err(authority_error());
        }
        let document: toml::Value = toml::from_str(text).map_err(|_| authority_error())?;
        let direct = document.get("security_assessment");
        let nested = document
            .get("tool")
            .and_then(|v| v.get("pybun"))
            .and_then(|v| v.get("security_assessment"));
        let section = match (direct, nested) {
            (Some(_), Some(_)) => return Err(authority_error()),
            (Some(value), None) | (None, Some(value)) => value.clone(),
            (None, None) => {
                return Ok(Self {
                    default_profile: None,
                    profiles: BTreeMap::new(),
                });
            }
        };
        let mut section: Section = section.try_into().map_err(|_| authority_error())?;
        if section.config_version != 1
            || section.profiles.len() > 64
            || section.providers.len() > 64
            || section.registries.len() > 64
            || section.source_policies.len() > 64
        {
            return Err(authority_error());
        }
        let (limits, max_output_bytes) =
            configured_limits(&ObservationLimits::default(), OUTPUT_BYTES, &section.limits)?;
        let credentials = section
            .providers
            .iter()
            .chain(section.registries.iter().map(|registry| &registry.provider))
            .filter_map(|endpoint| endpoint.bearer_token_env.as_ref())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|name| Ok((name.clone(), resolve_token(name)?)))
            .collect::<Result<BTreeMap<_, _>, ObservationDiagnostic>>()?;
        let mut providers = BTreeMap::new();
        let mut provider_ids = BTreeSet::new();
        for definition in &section.providers {
            if !provider_ids.insert(definition.id.clone()) {
                return Err(authority_error());
            }
            providers.insert(definition.id.clone(), definition.endpoint(&credentials)?);
        }
        let mut registries = BTreeMap::new();
        for definition in &section.registries {
            if !provider_ids.insert(definition.provider.id.clone())
                || registries.contains_key(&definition.source_id)
            {
                return Err(authority_error());
            }
            let mut source = RegistrySource::new(RegistrySourceConfig {
                source_id: definition.source_id.clone(),
                provider: definition.provider.config(),
            })?;
            if let Some(name) = &definition.provider.bearer_token_env {
                source =
                    source.with_bearer_token(credentials.get(name).ok_or_else(authority_error)?)?;
            }
            registries.insert(definition.source_id.clone(), source);
        }
        for (id, policy) in &mut section.source_policies {
            if !opaque_id(id) {
                return Err(authority_error());
            }
            *policy = canonical_policy(std::mem::take(policy))?;
            if policy
                .disclosure
                .iter()
                .any(|grant| !provider_ids.contains(&grant.provider_id))
            {
                return Err(authority_error());
            }
        }
        let base = base.canonicalize().map_err(|_| authority_error())?;
        let mut profiles = BTreeMap::new();
        for mut profile in section.profiles {
            if !opaque_id(&profile.id)
                || profiles.contains_key(&profile.id)
                || profile.allowed_modes.is_empty()
                || profile.max_cache_age_seconds > default_cache_age()
            {
                return Err(authority_error());
            }
            let policy = section
                .source_policies
                .get(&profile.source_policy_id)
                .ok_or_else(authority_error)?
                .clone();
            let mut selected_providers = unique_refs(&profile.provider_ids, &providers)?;
            let mut selected_sources = unique_refs(&profile.registry_source_ids, &registries)?;
            selected_providers.sort_by(|a, b| a.id().cmp(b.id()));
            selected_sources.sort_by(|a, b| a.source_id().cmp(b.source_id()));
            let approved_ids: BTreeSet<_> = selected_providers
                .iter()
                .map(|p| p.id())
                .chain(selected_sources.iter().map(|s| s.provider().id()))
                .collect();
            if policy
                .disclosure
                .iter()
                .any(|grant| !approved_ids.contains(grant.provider_id.as_str()))
                || selected_sources
                    .iter()
                    .any(|source| !policy.sources.iter().any(|s| s.id == source.source_id()))
            {
                return Err(authority_error());
            }
            for names in [
                &mut profile.scope.members,
                &mut profile.scope.groups,
                &mut profile.scope.extras,
            ] {
                names.sort();
                names.dedup();
            }
            profile.allowed_modes.sort_by_key(|mode| match mode {
                CheckMode::Online => 0,
                CheckMode::Offline => 1,
                CheckMode::OnlineWithCacheFallback => 2,
            });
            profile.allowed_modes.dedup();
            profile
                .registry_bindings
                .sort_by(|a, b| a.source_id.cmp(&b.source_id));
            let project = PinnedPath::new(&base, &profile.project_root, PathKind::Directory)?;
            let environment = PinnedPath::new(&base, &profile.environment, PathKind::Directory)?;
            let python = PinnedPath::new(&base, &profile.trusted_python, PathKind::Executable)?;
            let cache = profile
                .cache_root
                .as_ref()
                .map(|p| PinnedPath::new(&base, p, PathKind::PrivateDirectory))
                .transpose()?;
            let provenance = match (&profile.trusted_uv, &profile.provenance_cache_root) {
                (None, None) if profile.registry_bindings.is_empty() => None,
                (Some(executable), Some(cache)) if profile.backend == InventoryBackend::Uv => {
                    validate_bindings(&profile.registry_bindings, &policy, &selected_sources)?;
                    Some((
                        PinnedPath::new(&base, executable, PathKind::Executable)?,
                        PinnedPath::new(&base, cache, PathKind::PrivateDirectory)?,
                        profile.registry_bindings.clone(),
                    ))
                }
                _ => return Err(authority_error()),
            };
            let (profile_limits, profile_output) =
                configured_limits(&limits, max_output_bytes, &profile.limits)?;
            let permissions = ProfilePermissions {
                id: profile.id.clone(),
                project_root: project.canonical.clone(),
                environment_root: environment.canonical.clone(),
                backend: profile.backend,
                cache_root: cache.as_ref().map(|p| p.canonical.clone()),
            };
            let policy_digest = semantic_digest(&serde_json::json!({
                "version":1, "id":profile.id, "project":permissions.project_root,
                "environment":permissions.environment_root, "backend":profile.backend,
                "target":profile.target, "scope":profile.scope,
                "python":python.canonical, "python_digest":python.digest,
                "cache":permissions.cache_root, "source_policy":policy,
                "providers":selected_providers.iter().map(canonical_endpoint).collect::<Vec<_>>(),
                "registries":selected_sources.iter().map(|source|(source.source_id(),canonical_endpoint(source.provider()))).collect::<Vec<_>>(),
                "provenance":provenance.as_ref().map(|(executable,cache,bindings)|(&executable.canonical,&executable.digest,&cache.canonical,bindings)),
                "allowed_modes":profile.allowed_modes, "limits":profile_limits,
                "max_output_bytes":profile_output, "max_cache_age_seconds":profile.max_cache_age_seconds,
                "include_prereleases":profile.include_prereleases,
            }));
            profiles.insert(
                profile.id,
                Arc::new(FrozenProfile {
                    permissions,
                    policy_digest,
                    project,
                    environment,
                    python,
                    cache,
                    target: profile.target,
                    policy,
                    providers: selected_providers,
                    sources: selected_sources,
                    allowed_modes: profile.allowed_modes,
                    limits: profile_limits,
                    max_output_bytes: profile_output,
                    max_cache_age_seconds: profile.max_cache_age_seconds,
                    include_prereleases: profile.include_prereleases,
                    scope: profile.scope,
                    provenance,
                }),
            );
        }
        if section
            .default_profile
            .as_ref()
            .is_some_and(|id| !profiles.contains_key(id))
        {
            return Err(authority_error());
        }
        Ok(Self {
            default_profile: section.default_profile,
            profiles,
        })
    }

    /// Pure frozen lookup for generic transport grants; it does no filesystem I/O.
    pub fn profile_permissions(
        &self,
        profile: Option<&str>,
    ) -> Result<ProfilePermissions, ObservationDiagnostic> {
        Ok(self.selected(profile)?.permissions.clone())
    }
    fn selected(
        &self,
        profile: Option<&str>,
    ) -> Result<&Arc<FrozenProfile>, ObservationDiagnostic> {
        let id = profile
            .or(self.default_profile.as_deref())
            .ok_or_else(authority_error)?;
        self.profiles.get(id).ok_or_else(authority_error)
    }

    /// Convenience for synchronous operator callers. Authorization and service
    /// work share the absolute deadline established by preparation.
    pub fn authorize(
        &self,
        request: &CheckUpdatesRequest,
        operator_timeout_ms: Option<u64>,
    ) -> Result<AuthorizedCheck, ObservationDiagnostic> {
        self.prepare(request, operator_timeout_ms)?.authorize()
    }

    /// Select frozen grants and narrower budgets without filesystem access.
    /// Queueing and every subsequent authorization stage spend this deadline.
    pub fn prepare(
        &self,
        request: &CheckUpdatesRequest,
        operator_timeout_ms: Option<u64>,
    ) -> Result<PreparedCheck, ObservationDiagnostic> {
        if let Some(continuation) = &request.continuation {
            AssessmentContinuation::parse(continuation.as_str())?;
        }
        if request.target == CheckTarget::Locked {
            return Err(unsupported());
        }
        let profile = self.selected(request.profile.as_deref())?;
        if profile.target != CheckTarget::Installed {
            return Err(unsupported());
        }
        if !profile.scope.members.is_empty() {
            return Err(scope_error());
        }
        if !profile.allowed_modes.contains(&request.mode) {
            return Err(authority_error());
        }
        let mut limits = request
            .limits
            .clone()
            .unwrap_or_else(|| profile.limits.clone());
        limits.validate()?;
        check_narrower(&limits, &profile.limits)?;
        if let Some(cap) = operator_timeout_ms.filter(|value| *value > 0) {
            limits.total_timeout_ms = limits.total_timeout_ms.min(cap);
        }
        limits.http_timeout_ms = limits.http_timeout_ms.min(limits.total_timeout_ms);
        let age = request
            .max_cache_age_seconds
            .unwrap_or(profile.max_cache_age_seconds);
        if age > profile.max_cache_age_seconds {
            return Err(limit_error());
        }
        let deadline = Instant::now() + Duration::from_millis(limits.total_timeout_ms);
        Ok(PreparedCheck {
            profile: Arc::clone(profile),
            request: request.clone(),
            limits,
            max_cache_age_seconds: age,
            deadline,
        })
    }
}

/// Purely selected frozen grants with one absolute end-to-end deadline.
/// It is neither deserializable nor a proof that current paths remain authorized.
pub struct PreparedCheck {
    profile: Arc<FrozenProfile>,
    request: CheckUpdatesRequest,
    limits: ObservationLimits,
    max_cache_age_seconds: u64,
    deadline: Instant,
}
impl PreparedCheck {
    pub fn permissions(&self) -> ProfilePermissions {
        self.profile.permissions.clone()
    }
    pub fn limits(&self) -> &ObservationLimits {
        &self.limits
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn max_output_bytes(&self) -> usize {
        self.profile.max_output_bytes
    }

    /// Revalidate current grants before admitting any cache, helper, or HTTP work.
    pub fn authorize(self) -> Result<AuthorizedCheck, ObservationDiagnostic> {
        let Self {
            profile,
            request,
            limits,
            max_cache_age_seconds: age,
            deadline,
        } = self;
        let profile = profile.as_ref();
        check_deadline(Some(deadline))?;
        if let Some(project) = &request.project
            && project.canonicalize().map_err(|_| authority_error())? != profile.project.canonical
        {
            return Err(authority_error());
        }
        profile.project.revalidate(deadline)?;
        profile.environment.revalidate(deadline)?;
        validate_scope(profile, &limits, deadline)?;
        profile.python.revalidate(deadline)?;
        if let Some(cache) = &profile.cache {
            cache.revalidate(deadline)?;
        }
        check_deadline(Some(deadline))?;
        profile.policy.validate()?;
        let provenance = if let Some((uv, cache, bindings)) = &profile.provenance {
            uv.revalidate(deadline)?;
            cache.revalidate(deadline)?;
            validate_bindings(bindings, &profile.policy, &profile.sources)?;
            Some((
                ProvenanceRequest {
                    trusted_uv: uv.canonical.clone(),
                    approved_cache_root: cache.canonical.clone(),
                    authorized_roots: vec![
                        profile.project.canonical.clone(),
                        profile.environment.canonical.clone(),
                    ],
                    limits: limits.clone(),
                },
                bindings.clone(),
            ))
        } else {
            None
        };
        check_deadline(Some(deadline))?;
        let authorized = AuthorizedCheck {
            deadline,
            inventory: InventoryRequest {
                project_root: profile.project.canonical.clone(),
                environment: Some(profile.environment.canonical.clone()),
                trusted_python: profile.python.canonical.clone(),
                target: InventoryTarget::Installed,
                backend: profile.permissions.backend,
                scope: profile.scope.clone(),
                source_policy: profile.policy.clone(),
                limits: limits.clone(),
            },
            providers: profile.providers.clone(),
            sources: profile.sources.clone(),
            mode: request.mode.into(),
            cache_root: profile.cache.as_ref().map(|p| p.canonical.clone()),
            max_cache_age_seconds: age,
            include_prereleases: profile.include_prereleases,
            continuation: request.continuation.clone(),
            fail_on: request.fail_on,
            profile_id: profile.permissions.id.clone(),
            policy_digest: semantic_digest(&(&profile.policy_digest, &limits, age, request.mode)),
            max_output_bytes: profile.max_output_bytes,
            provenance,
        };
        check_deadline(Some(deadline))?;
        Ok(authorized)
    }
}

fn canonical_endpoint(endpoint: &ProviderEndpoint) -> ProviderConfig {
    let mut config = endpoint.config().clone();
    config.url = endpoint.url().as_str().into();
    config
}
fn canonical_policy(mut policy: SourcePolicy) -> Result<SourcePolicy, ObservationDiagnostic> {
    policy.validate()?;
    policy.sources.sort_by(|a, b| a.id.cmp(&b.id));
    let mut rules = BTreeSet::new();
    for rule in &mut policy.rules {
        rule.name = super::normalize_name(&rule.name)?;
        if !rules.insert((rule.name.clone(), rule.distribution.clone())) {
            return Err(authority_error());
        }
        rule.upstream_name = rule
            .upstream_name
            .as_ref()
            .map(|name| super::normalize_name(name))
            .transpose()?;
    }
    policy.rules.sort_by_key(semantic_digest);
    for grant in &mut policy.disclosure {
        grant.packages = grant
            .packages
            .iter()
            .map(|name| super::normalize_name(name))
            .collect::<Result<_, _>>()?;
        grant.packages.sort();
        grant.packages.dedup();
    }
    policy.disclosure.sort_by_key(semantic_digest);
    policy.disclosure.dedup();
    Ok(policy)
}

fn validate_scope(
    profile: &FrozenProfile,
    limits: &ObservationLimits,
    deadline: Instant,
) -> Result<(), ObservationDiagnostic> {
    check_deadline(Some(deadline))?;
    if profile.scope.extras.is_empty() && profile.scope.groups.is_empty() {
        return Ok(());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    check_deadline(Some(deadline))?;
    let mut file = options
        .open(profile.project.canonical.join("pyproject.toml"))
        .map_err(|_| scope_error())?;
    check_deadline(Some(deadline))?;
    let metadata = file.metadata().map_err(|_| scope_error())?;
    if !metadata.is_file() || metadata.len() > limits.max_metadata_bytes as u64 {
        return Err(scope_error());
    }
    let mut bytes = Vec::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        check_deadline(Some(deadline))?;
        let remaining = limits.max_metadata_bytes.saturating_sub(bytes.len()) + 1;
        let chunk_bytes = remaining.min(buffer.len());
        let size = file
            .read(&mut buffer[..chunk_bytes])
            .map_err(|_| scope_error())?;
        if size == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..size]);
        if bytes.len() > limits.max_metadata_bytes {
            return Err(scope_error());
        }
    }
    check_deadline(Some(deadline))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| scope_error())?;
    let project: toml::Value = toml::from_str(text).map_err(|_| scope_error())?;
    check_deadline(Some(deadline))?;
    super::inventory::direct_constraints(&project, &profile.scope, &bytes)?;
    profile.project.revalidate(deadline)
}
fn scope_error() -> ObservationDiagnostic {
    ObservationDiagnostic::new(
        "E_SECURITY_UNSUPPORTED_SCOPE",
        "The configured project scope is unsupported or no longer available; no helper or provider access was authorized.",
    )
}

fn unique_refs<T: Clone>(
    ids: &[String],
    items: &BTreeMap<String, T>,
) -> Result<Vec<T>, ObservationDiagnostic> {
    let mut seen = BTreeSet::new();
    ids.iter()
        .map(|id| {
            if !seen.insert(id) {
                return Err(authority_error());
            }
            items.get(id).cloned().ok_or_else(authority_error)
        })
        .collect()
}
fn configured_limits(
    base: &ObservationLimits,
    base_output: usize,
    values: &BTreeMap<String, u64>,
) -> Result<(ObservationLimits, usize), ObservationDiagnostic> {
    let mut object = serde_json::to_value(base).map_err(|_| limit_error())?;
    let table = object.as_object_mut().ok_or_else(limit_error)?;
    let mut output = base_output;
    for (name, value) in values {
        if name == "max_output_bytes" {
            output = usize::try_from(*value).map_err(|_| limit_error())?;
            if output < 4096 || output > base_output {
                return Err(limit_error());
            }
        } else {
            let current = table.get_mut(name).ok_or_else(limit_error)?;
            if *value == 0 || *value > current.as_u64().ok_or_else(limit_error)? {
                return Err(limit_error());
            }
            *current = serde_json::json!(value);
        }
    }
    let limits: ObservationLimits = serde_json::from_value(object).map_err(|_| limit_error())?;
    limits.validate()?;
    Ok((limits, output))
}
fn check_narrower(
    request: &ObservationLimits,
    cap: &ObservationLimits,
) -> Result<(), ObservationDiagnostic> {
    let requested = serde_json::to_value(request).map_err(|_| limit_error())?;
    let maximum = serde_json::to_value(cap).map_err(|_| limit_error())?;
    if requested
        .as_object()
        .ok_or_else(limit_error)?
        .iter()
        .any(|(key, value)| value.as_u64() > maximum[key].as_u64())
    {
        return Err(limit_error());
    }
    Ok(())
}
fn validate_bindings(
    bindings: &[ApprovedRegistryBinding],
    policy: &SourcePolicy,
    sources: &[RegistrySource],
) -> Result<(), ObservationDiagnostic> {
    let mut seen = BTreeSet::new();
    for binding in bindings {
        let source = policy
            .sources
            .iter()
            .find(|s| s.id == binding.source_id && s.auth_scope_id == binding.auth_scope_id)
            .ok_or_else(authority_error)?;
        let registry = sources
            .iter()
            .find(|s| s.source_id() == source.id)
            .ok_or_else(authority_error)?;
        let endpoint = ProviderEndpoint::new(ProviderConfig {
            id: "binding".into(),
            auth_scope_id: binding.auth_scope_id.clone(),
            url: binding.registry_url.clone(),
            allow_insecure_loopback: registry.provider().config().allow_insecure_loopback,
        })?;
        if !seen.insert(&binding.source_id)
            || endpoint.url().as_str().trim_end_matches('/')
                != registry.provider().url().as_str().trim_end_matches('/')
        {
            return Err(authority_error());
        }
    }
    Ok(())
}
fn resolve_token(name: &str) -> Result<String, ObservationDiagnostic> {
    if name.is_empty()
        || name.len() > 128
        || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
    {
        return Err(authority_error());
    }
    let token = std::env::var(name).map_err(|_| authority_error())?;
    if token.is_empty() || token.len() > 8192 {
        return Err(authority_error());
    }
    Ok(token)
}
fn online_modes() -> Vec<CheckMode> {
    vec![CheckMode::Online]
}
fn default_cache_age() -> u64 {
    86400
}
fn authority_error() -> ObservationDiagnostic {
    ObservationDiagnostic::new(
        "E_SECURITY_AUTHORITY",
        "The selected security-check profile or its current operator grant is unavailable or invalid.",
    )
}
fn limit_error() -> ObservationDiagnostic {
    ObservationDiagnostic::new(
        "E_SECURITY_LIMIT",
        "Security-check bounds may only narrow the current operator profile and service limits.",
    )
}
fn unsupported() -> ObservationDiagnostic {
    ObservationDiagnostic::new(
        "E_SECURITY_UNSUPPORTED_INVENTORY",
        "Locked inventory has no supported read-only adapter; no fallback was authorized.",
    )
}

#[derive(Clone, Copy)]
enum PathKind {
    Directory,
    PrivateDirectory,
    Executable,
}
struct PinnedPath {
    configured: PathBuf,
    canonical: PathBuf,
    identity: FileIdentity,
    kind: PathKind,
    digest: Option<String>,
}
#[derive(PartialEq, Eq)]
struct FileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    owner: u32,
    #[cfg(unix)]
    mode: u32,
}
impl FileIdentity {
    fn from(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                owner: metadata.uid(),
                mode: metadata.mode(),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            Self {}
        }
    }
}
impl PinnedPath {
    fn new(base: &Path, path: &Path, kind: PathKind) -> Result<Self, ObservationDiagnostic> {
        if !cfg!(unix) {
            return Err(authority_error());
        }
        let configured = if path.is_absolute() {
            path.to_owned()
        } else {
            base.join(path)
        };
        let canonical = configured.canonicalize().map_err(|_| authority_error())?;
        if matches!(kind, PathKind::PrivateDirectory)
            && std::fs::symlink_metadata(&configured)
                .map_err(|_| authority_error())?
                .file_type()
                .is_symlink()
        {
            return Err(authority_error());
        }
        let (identity, digest) = Self::current(&canonical, kind, None)?;
        Ok(Self {
            configured,
            canonical,
            identity,
            kind,
            digest,
        })
    }
    fn current(
        path: &Path,
        kind: PathKind,
        deadline: Option<Instant>,
    ) -> Result<(FileIdentity, Option<String>), ObservationDiagnostic> {
        check_deadline(deadline)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(
                libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | if matches!(kind, PathKind::Executable) {
                        0
                    } else {
                        libc::O_DIRECTORY
                    },
            );
        }
        check_deadline(deadline)?;
        let mut file = options.open(path).map_err(|_| authority_error())?;
        check_deadline(deadline)?;
        let metadata = file.metadata().map_err(|_| authority_error())?;
        check_deadline(deadline)?;
        let current = std::fs::symlink_metadata(path).map_err(|_| authority_error())?;
        if current.file_type().is_symlink()
            || FileIdentity::from(&metadata) != FileIdentity::from(&current)
        {
            return Err(authority_error());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // SAFETY: geteuid has no pointer arguments or caller preconditions.
            let uid = unsafe { libc::geteuid() };
            match kind {
                PathKind::PrivateDirectory
                    if !metadata.is_dir()
                        || metadata.uid() != uid
                        || metadata.mode() & 0o077 != 0 =>
                {
                    return Err(authority_error());
                }
                PathKind::Directory if !metadata.is_dir() => return Err(authority_error()),
                PathKind::Executable
                    if !metadata.is_file()
                        || metadata.mode() & 0o111 == 0
                        || metadata.mode() & 0o022 != 0
                        || (metadata.uid() != uid && metadata.uid() != 0)
                        || metadata.len() > EXECUTABLE_BYTES =>
                {
                    return Err(authority_error());
                }
                _ => {}
            }
        }
        let digest = if matches!(kind, PathKind::Executable) {
            let mut digest = Sha256::new();
            let mut remaining = EXECUTABLE_BYTES + 1;
            let mut buffer = [0; 64 * 1024];
            while remaining > 0 {
                check_deadline(deadline)?;
                let size = file
                    .read(&mut buffer[..remaining.min(64 * 1024) as usize])
                    .map_err(|_| authority_error())?;
                if size == 0 {
                    break;
                }
                remaining -= size as u64;
                digest.update(&buffer[..size]);
            }
            check_deadline(deadline)?;
            let after = file.metadata().map_err(|_| authority_error())?;
            if remaining == 0
                || metadata.len() != after.len()
                || metadata.modified().ok() != after.modified().ok()
            {
                return Err(authority_error());
            }
            Some(hex::encode(digest.finalize()))
        } else {
            None
        };
        check_deadline(deadline)?;
        Ok((FileIdentity::from(&metadata), digest))
    }
    fn revalidate(&self, deadline: Instant) -> Result<(), ObservationDiagnostic> {
        check_deadline(Some(deadline))?;
        if self
            .configured
            .canonicalize()
            .map_err(|_| authority_error())?
            != self.canonical
        {
            return Err(authority_error());
        }
        let (identity, digest) = Self::current(&self.canonical, self.kind, Some(deadline))?;
        if identity != self.identity || digest != self.digest {
            return Err(authority_error());
        }
        check_deadline(Some(deadline))
    }
}

fn check_deadline(deadline: Option<Instant>) -> Result<(), ObservationDiagnostic> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return Err(ObservationDiagnostic::new(
            "E_SECURITY_DEADLINE",
            "The observation deadline was exhausted.",
        ));
    }
    Ok(())
}
