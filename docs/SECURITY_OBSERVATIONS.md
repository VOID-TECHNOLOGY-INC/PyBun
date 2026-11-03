# Dependency security observations

`security_assessment` is the read-only library foundation for security update
checks. The existing `audit` command retains its existing behavior. This module
does not install packages, invoke a solver, change locks, create an execution
receipt, or deliver notifications.

## Selecting an installed environment

Construct `InventoryRequest::installed(project_root, trusted_python)` and call
`observe_inventory(&request, observed_at)`. The caller explicitly trusts the
CPython executable; it must match the selected environment interpreter by
canonical executable identity or byte-for-byte executable digest. The selected
interpreter is never executed. The trusted helper runs fixed embedded code with
`-I -S -B`, an empty environment, bounded input/output and a process-tree deadline.

The default selected environment is `.venv` for the UV backend. The native
backend selects `.pybun/venv`; `environment` can select an explicit path. Both
read the selected environment's `pyvenv.cfg` and explicit site-packages directory,
not `sys.prefix` (whose behavior under `-S` differs between Python versions).
There is no fallback to system Python, pip, uv, lock inventory, or package imports.
The caller must authorize the canonical project/environment/interpreter paths
before using this library across a security boundary.

The supported initial layout is a matching CPython venv on Linux or macOS with
`lib/pythonX.Y/site-packages`; the Windows `Lib/site-packages` adapter requires
an independently proven matching executable and is not covered by the current
runtime CI matrix. CI exercises CPython 3.8, 3.11, 3.13 and 3.14, including the
3.14 `-S` prefix change. PyPy, locked/system targets, system-site environments,
unknown layouts, workspace member constraint aggregation and included dependency
groups return coded incomplete results. Root dependencies, selected extras and
string dependency groups retain their raw requirement/provenance evidence.
Installed distributions are never filtered by these declarations or `uv.lock`.

Every top-level `.dist-info` and `.egg-info` distribution is observed separately,
including multiple versions and unlocked extras. Metadata is read through a
scoped directory capability, rejecting symlinks and nonregular files, with
nonblocking/no-follow file opens on Unix. No `.pth`, sitecustomize,
usercustomize, project module, plugin, entry point or build hook is executed.
Nonempty `.pth` path/code entries and `.egg-link` files mark the inventory
`partial`: they could expose additional distributions, and their destinations
are not traversed. Empty/comment-only files are harmless. This includes UV's
usual `_virtualenv.pth` hook; observed package facts remain available with their
own completeness. Do not remove environment hooks to obtain a complete result.

Target tags come from pinned, licensed PyPA packaging sources embedded in memory:
25.0 for Python 3.8 and 26.3 for newer interpreters. The result records the full
sorted tag set, generator/version, profile version and digest, implementation,
version, OS, architecture, libc and deployment information. This is an exact tag
set, not a fabricated universal-wheel profile. Vendor READMEs contain source
URLs and hashes; updates must preserve the versions, licenses and profile tests.

## Source identity and permission

`SourcePolicy` contains three independent declarations:

- `sources`: opaque source and authorization-scope identities; never URLs or credentials.
- `rules`: normalized installed name, optional exact distribution basename and an
  explicit upstream ecosystem/name/visible assumption. A private mirror needs
  this mapping; an endpoint URL alone does not establish PyPI equivalence.
- `disclosure`: package identities permitted to be sent to a particular provider.

Mapping and disclosure must both succeed before an `AuthorizedQuery` can be
created. The query proof cannot be deserialized or constructed by external
callers. Current rules are rechecked against the exact distribution evidence,
so a revoked distribution-specific rule cannot reuse another distribution's
mapping. Specific rules override generic rules; ambiguous rules are errors.

An unknown source remains an inventory fact with partial source applicability.
Allowing disclosure never turns a same-name private fork into a public package.
Direct URL, VCS and editable origins retain their kind and are not erased by a
public-name assumption. Their opaque origin digest strips URL credentials,
query and fragment, while distinguishing origin paths, VCS commits, subdirectories
and editable state. Credential rotation preserves semantic identity; raw metadata
digests still show that evidence changed. No direct URL is fetched.

## Advisory observations and completeness

`ProviderEndpoint` validates approved HTTPS endpoints (explicit loopback HTTP is
available for local fixtures). Bearer credentials are attached only in memory,
never serialized, and cannot cross an origin or path boundary. HTTP redirects,
URL credentials, inherited proxy credentials, compressed response amplification,
unapproved derived URLs and advisory reference fetching are prohibited.
`HttpSession` enforces request/page/attempt/concurrency/response/deadline limits.
Callers can narrow the default ceilings, not increase them.

Each JSON response is capped at 5 MiB. Retained registry/advisory observations
share a separate 50 MiB run budget (`max_retained_evidence_bytes`), including
later candidate re-queries. Both caps can only be narrowed. Keeping these units
separate permits a large valid index response while bounding accumulation and
record duplication across providers; exhaustion is incomplete evidence.

OSV observations remap each instance under current policy before disclosure.
They preserve full hydrated advisory JSON, IDs/aliases, raw payload digest,
fetch time, provider/source provenance, pagination and per-instance coverage.
Failed pages, hydration, exhausted budgets and inherited incomplete inventory
remain explicit incomplete evidence. Validated empty inventory is distinct from
missing or unreadable inventory. A negative finding requires complete evidence;
partial input must never be treated as proof of absence.

The shared coverage units are `inventory_instances`, `advisory_records`,
`finding_clusters` and `candidate_checks`. Inventory counts enumerate actual
metadata instances; unknown path extensions have no invented package count.
Per-instance facts and aggregate completeness must both be inspected.
`inventory_id` identifies semantic inventory/target facts and excludes fetch
clocks and raw-evidence digests. `observation_id`, environment fingerprints and
raw project/lock/metadata digests preserve capture differences. No successful
mutation receipt is produced by observation.

## Verification

`cargo test --test security_observations --test security_observation_providers`
exercises real venvs, startup sentinels, source policy, unchanged file hashes,
limits, unsafe metadata paths and local HTTP servers. With the supported uv
executable already installed, run the actual backend fixture explicitly:

```sh
cargo test --test security_observations actual_uv_environment -- --ignored
```

`PYBUN_SECURITY_TEST_PYTHON` selects the trusted Python used by test fixtures;
it does not affect the production library. CI installs its own test tools before
creating fixture environments; observation itself never bootstraps tools.

### Prerelease interpreter qualification

The target Python version preserves CPython's release level and serial, for
example `3.15.0rc2`, so a wheel requiring `>=3.15` is not qualified for that
prerelease. The numeric three-component `version` written by stdlib `venv` is
only a release-component hint: CPython writes that lossy form even for release
candidates. The proven matching trusted executable supplies the complete version.
Explicit UV PEP 440 versions and recognized five-component CPython versions must
match in full. Unknown trailing components, conflicting version declarations and
an explicit prerelease paired with a stable executable are rejected.

The normal suite checks configuration tails against an installed stable Python.
The explicit runtime regressions additionally require a separately provisioned
prerelease executable; they never install one themselves. A macOS arm64
CPython `3.15.0rc2` fixture was exercised with both stdlib and UV-created venvs.
To repeat with a test-only installation outside project and user environments:

```sh
uv --no-config --cache-dir /tmp/pybun-prerelease-cache python install \
  --install-dir /tmp/pybun-prerelease-python --no-bin --no-registry 3.15.0rc2
PYBUN_SECURITY_PRERELEASE_PYTHON=/tmp/pybun-prerelease-python/cpython-3.15.0rc2-macos-aarch64-none/bin/python3.15 \
  cargo test --test security_python_prerelease -- --include-ignored
```

The executable path varies by platform. These opt-in runtime tests verify the
full observed version, executable proof and actual `Requires-Python` decisions;
prerelease availability is not inferred from a synthetic target profile.

### Exact marker environment

`ObservedTarget.marker_environment` records all eleven canonical PEP 508 values:
`implementation_name`, `implementation_version`, `os_name`, `platform_machine`,
`platform_python_implementation`, `platform_release`, `platform_system`,
`platform_version`, `python_full_version`, `python_version` and `sys_platform`.
The fixed isolated helper observes these through the trusted CPython standard
library. `platform_machine` retains its original case; it is not reconstructed
from the lowercase architecture display value. Full Python and implementation
versions preserve prerelease information.

The maintained `pep508_rs` marker-environment builder validates version values;
missing, malformed or internally inconsistent environments return coded
unsupported evidence. There are no fabricated empty defaults. Marker values
participate in the semantic inventory identity and environment fingerprint so a
changed marker context cannot reuse an older target assessment silently.

`cargo test --test security_marker_environment` compares a real venv observation
with an independent isolated standard-library probe. A separate controlled-helper
fixture injects the reported machine string `AMD64` and verifies case-sensitive
marker comparisons; it is a formatting test, not evidence of an AMD64 host.
The same real-venv observation test can be repeated on the explicitly provisioned
prerelease executable by setting `PYBUN_SECURITY_TEST_PYTHON` to its path.

## Candidate assessment service

`qualification::service::assess_project` observes the installed environment with
its explicitly trusted interpreter, then uses one `HttpSession` for current and
candidate advisory queries and approved-source JSON Simple metadata. Optional
frozen graph provenance uses the remaining run deadline and its private cache
profile. `assess_inventory` accepts an already observed inventory for callers
that have performed the same target authorization. These are library entry
points; the legacy audit command and its JSON contract remain unchanged.

A candidate requires a non-yanked compatible wheel from the same approved
source and the exact observed target-tag profile. File URLs are evidence only:
assessment does not fetch archives, run build hooks, install, resolve or verify
an updated environment. Prerelease and development releases are excluded from
discovery unless explicitly requested. Exact previous candidates are still
revalidated when they fall outside the current discovery subset.

Applicable OSV ranges and explicit versions are unioned using PEP 440 semantics.
`published_remediation_candidate` additionally requires a relevant explicit
fixed boundary for the installed version and complete fresh candidate queries
against every configured authoritative provider. Current-query records are
also evaluated at the candidate version, so omission from a candidate query
cannot erase known reintroduction. Conflicting revisions, withdrawals and
incomplete candidate-provider evidence retain their diagnostics and prevent a
fresh fix assertion.
An observed unaffected upgrade without explicit fixed evidence is
`non_affected_upgrade_observed`. Missing fix information is not proof that no
upstream fix exists.

Candidates retain direct requirement blockers and their origins/digests.
`metadata_recommendations` separately lists qualified candidates that pass known
direct constraints. Full and transitive constraint completeness remains unknown;
resolution is always `not_checked`, and verification is always `not_run`.
Per-source/instance advisory clusters retain every contributing provider,
record, alias and payload digest. Unknown severity is not converted into an
invented numeric CVSS score. Inventory, advisory-record, finding-cluster and
candidate-check coverage are reported separately from aggregate status.

Continuation tokens bind inventory, scope, provider/source configuration,
policy, target tags and assessment revision. They control traversal only and
cannot prove exclusions or a minimum. Discovery and previous-candidate work
share the run budget, with separate traversal positions. Only the observed
prefix of each package advances; a request-budget miss does not silently skip
its versions. Missing registry metadata preserves the previous discovery
position, and circular metadata priority advances after actual requests.
Unrevalidated previous candidates remain explicit in
`pending_previous_candidates`. `lowest_proven_candidate` requires complete
current enumeration and conclusive exclusion of every lower in-policy release;
otherwise only the lowest assessed candidate is reported.

## Optional observation cache and freshness

Cache access requires an explicitly approved canonical directory owned by the
current user with private permissions. The service pins that directory and uses
bounded regular files, no-follow reads, private temporary files, file fsync,
atomic replacement and directory fsync. It never creates a project cache or
receipt. Windows reports the cache profile as unsupported. Corrupt, mismatched,
future-schema and future-timestamp entries are errors, not empty observations.

Cache keys bind the source, provider endpoint, authorization scope, query and
schema; bearer bytes are excluded. HTTP responses are redacted before writing,
and cache hits are redacted again for the current endpoint credentials.
Explicit credentials are protected even in typed fields, object keys, short
embedded strings and equivalent scalar values. Payload digests retain original
response provenance; a separate cache digest detects stored-envelope corruption.
The cache is user-controlled evidence, not an authorization source.

Online mode always requests fresh evidence. Offline mode performs no HTTP and
reports `offline_cache`, the original fetch time and age. Explicit online
fallback reports `stale_cache` and the failed fresh request. Cache data never
becomes authoritative merely because its payload is structurally complete.
Cached positives remain visible, but cannot establish a newly observed patch or
an authoritative monitor transition. Cache write failures preserve successful
HTTP evidence and add an operational diagnostic; aggregate status remains
partial. All cache operations remain subject to the shared run deadline.

Candidate result axes are independent. `fix_evidence` is `known_boundary`,
`unavailable` or `unsupported`; it is not an assertion that a compatible artifact
was published. `availability` is `published_candidate`, `not_observed`, `unknown`
or `source_build_required`. The separate `candidate_kind` is either
`published_remediation_candidate`, `non_affected_upgrade_observed`, or null.
Only published remediation has a nonempty `published_remediation_basis`, tying
fresh qualifying boundaries to their exact provider/record/range/event evidence.
Resolution and verification have singleton status types, so a serialized result
cannot acquire an unperformed resolver or verification status.

All same-instance/source/auth-scope/mapping/provider records discovered in any
candidate query are re-evaluated for both installed and candidate versions,
including earlier candidates. Query omission cannot erase a range discovered
at another candidate. Withdrawn corrections remain explicit even when cached;
a cached ordinary negative for a different version is not required to establish
an independently fresh result. A fresh current affected/fixed witness plus
complete fresh candidate queries from every authoritative provider can establish
a positive remedy while another current-version query remains incomplete.
Current negative/clearance coverage and aggregate status remain partial.

Work and output budgets both affect traversal. Candidate queries and result
retention follow the same circular package/version order. Successful checkpoints
advance only an observed prefix whose assessment was actually retained. A failed package does
not consume the result budget of every later package. Current-version queries
first hydrate one witness, then defer their remaining pages/details until after
candidate bundles, so a large current advisory list cannot consume every
candidate opportunity. Mutable wheel URLs, hashes and requirements do not reset
release-version positions; release-set digests use semantic PEP 440 keys.

Pagination preserves the exact noncredential cursor returned by the provider.
If credential redaction changes a functional cursor, the response remains
incomplete; the service never substitutes the redacted text in a new request.
An individually attempted follow-up page counts as traversal work even when
pagination remains incomplete and returns no advisory IDs. That progress does
not make the candidate authoritative.

The continuation also holds a bounded scheduling width. When a leading admitted
frame cannot complete, later runs halve this width toward one package and one
candidate, narrowing registry/current-version admission and candidate admission
together. Deferred packages retain their discovery and prior-candidate positions.
A frame still too large at the minimum width rotates traversal to later work,
with explicit incomplete diagnostics and pending prior candidates. This retry
position is not an observed exclusion or proof of a lowest candidate. Unsupported
or unavailable registry enumeration preserves the previous discovery position;
current metadata evidence remains incomplete. Out-of-policy prior versions are
still revalidated, but do not enter the default recommendation/minimum selection.

The shared absolute deadline includes waiting for an inventory or optional graph
worker. Expired queued work cannot launch its helper or begin graph observation.
Graph timeout preserves already observed candidate facts and reports partial
coverage; it cannot extend the check merely because the blocking pool is busy.
