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
