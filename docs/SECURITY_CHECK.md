# Read-only security update checks

`pybun audit check-updates` observes an explicitly approved installed environment,
known advisories, and published candidate releases. It does not install, sync,
resolve, build, refresh a lock, apply updates, or register a monitor. Ordinary
`pybun audit` retains its flags, exit behavior, and JSON schema v1.

The shared CLI/MCP operation uses envelope v2, `detail.contract_version: "2"`,
and `assessment_version: 1`. An observed candidate is neither a resolver result
nor a tested remedy: `resolution_status` remains `not_checked` and
`verification_status` remains `not_run`. There is no automatic update, notification
delivery, scheduler installation, or security-upgrade `next_action`.

## Explicit operator authority

The CLI requires `--security-config PATH`; merely running inside a project never
trusts its source mappings, interpreter, endpoints, or cache paths. Missing
configuration returns a coded operational error. The selected file is bounded,
strict TOML containing `[security_assessment]` or
`[tool.pybun.security_assessment]`. Unknown fields and ambiguous identities fail
closed. Relative paths are resolved against that file's directory.

A profile freezes the project and environment roots, exact trusted interpreter,
backend, scope, provider/index identities, source/disclosure policy, cache roots,
and resource bounds. The trusted CPython executable must already be provisioned
and match the inspected environment's interpreter. The operation does not discover
or download a replacement. There is no system-environment fallback.

The following is an operator configuration example, not a runnable fixture or a
claim that these local paths exist. Approve each package's actual source identity
before adding a rule; a matching public package name alone is insufficient.

```toml
[security_assessment]
config_version = 1
default_profile = "app"

[[security_assessment.profiles]]
id = "app"
project_root = "/srv/app"
environment = "/srv/app/.venv"
target = "installed"
backend = "uv"
trusted_python = "/opt/operator/python3.13"
source_policy_id = "approved-app"
provider_ids = ["osv-public"]
registry_source_ids = ["public-pypi"]
cache_root = "/var/lib/pybun/security-cache/app"
allowed_modes = ["online", "offline", "online_with_cache_fallback"]
max_cache_age_seconds = 86400
include_prereleases = false
scope = { members = [], groups = [], extras = [] }

[[security_assessment.providers]]
id = "osv-public"
url = "https://api.osv.dev/v1/querybatch"
auth_scope_id = "public"
# Optional: bearer_token_env = "OPERATOR_OSV_TOKEN"

[[security_assessment.registries]]
source_id = "public-pypi"
provider = { id = "pypi-simple", url = "https://pypi.org/simple/", auth_scope_id = "public" }

[security_assessment.source_policies.approved-app]
sources = [{ id = "public-pypi", auth_scope_id = "public", kind = "public_registry" }]
rules = [
  { name = "six", source_id = "public-pypi", upstream_name = "six", ecosystem = "PyPI", assumption = "Operator confirms this distribution's public-PyPI identity." },
]
disclosure = [
  { provider_id = "osv-public", source_id = "public-pypi", packages = ["six"] },
  { provider_id = "pypi-simple", source_id = "public-pypi", packages = ["six"] },
]

[security_assessment.limits]
total_timeout_ms = 60000
http_timeout_ms = 10000
max_output_bytes = 5242880
```

Source equivalence and disclosure are independent permissions. Approving a
provider's receipt of a name does not make a private fork equivalent to PyPI.
Registry disclosure uses the installed distribution's identity; advisory disclosure
uses its explicitly mapped upstream identity. Unknown/private distributions remain
visible as incomplete evidence without being silently sent to public services.
Direct-URL and VCS origins are evidence, not permission to fetch those URLs.

Credentials referenced through `bearer_token_env` are captured at authority load
and held in memory; they are not serialized into the result. Requests cannot
replace endpoints, source rules, disclosure grants, trusted executables, cache
roots, or the server policy. Approved HTTP endpoints do not follow redirects or
inherit ambient proxy credentials. Insecure loopback HTTP is available only through
an explicit operator fixture setting; it is not a request-level relaxation.

Cache directories must already exist, be private to the operator, and satisfy the
cache adapter's owner/mode/no-follow checks. The check does not create an arbitrary
cache directory selected by a client. An online profile may omit `cache_root`;
offline and cache-fallback modes then return operational error 3 with no provider
request. Only approved observation/provenance cache writes are permitted; project,
lock, environment, monitor state, and execution receipts remain unchanged. MCP
security-check audit records are kept in memory rather than the generic durable
audit log, including rejected and rate-limited checks.

## Running a check

```sh
pybun --format=json audit check-updates \
  --security-config /etc/pybun/security.toml --profile app --target installed

pybun --format=json audit check-updates \
  --security-config /etc/pybun/security.toml --profile app \
  --mode offline --max-cache-age-seconds 3600 --fail-on high
```

`--project` may name the already approved project; it cannot retarget the profile.
`--timeout-ms` narrows the shared deadline. A returned assessment continuation can
be passed using `--continuation`; it is a bounded, domain-bound discovery cursor,
not a monitor event replay cursor. Input/domain changes can invalidate it.

`--target locked` is recognized but currently returns unsupported status and exit
3. It never switches silently to installed inventory. The installed profile
observes every discovered metadata instance, including packages absent from the
lock. Unsupported environment layouts or scope combinations remain explicit;
see [the observation contract](SECURITY_OBSERVATIONS.md).

CLI modes are `online`, `offline`, and `online-with-cache-fallback`. MCP uses the
JSON spelling `online_with_cache_fallback`. Offline mode makes zero provider
requests. Cache evidence remains labeled `offline_cache` or `stale_cache`, with
its age; it is not authoritative fresh evidence. The cache age ceiling defaults
to 86,400 seconds and cannot exceed that value. A profile or request can only
narrow it. Expired entries produce coded incomplete evidence, not a clean scan.

The operation shares one absolute deadline across current authorization,
inventory/helper work, bounded HTTP, optional provenance, semantic finalization,
and result preparation. Effective limits are the minimum of the request, service
defaults, profile, and applicable server cap. Smaller byte/request/deadline caps
are restrictions; they are not claims of OS memory, CPU, or sandbox enforcement.
After authorization, observation reserves ten percent of the remaining duration
(at most 250 ms) for finalizing partial evidence. A late provider timeout can
therefore return already observed threshold matches and traversal progress
without extending the whole-request deadline.

## MCP setup

`pybun_security_check` is denied by default. The server freezes the authority
section from its operator-selected policy document at startup; clients cannot
provide a config path or reload it. Prefer an explicitly selected operator file:

```sh
PYBUN_MCP_POLICY=/etc/pybun/security.toml pybun mcp serve --stdio
```

Add the following to the same document as the authority section. The example
grants this profile's metadata and approved HTTP operations, not arbitrary
subprocess or network access:

```toml
[mcp.policy]
require_sandbox = false
allow_network = true
max_execution_time_s = 30
max_memory_mb = 0
max_cpu_time_s = 0
allowed_working_directories = ["/srv/app"]
allowed_backends = ["uv"]
allowed_security_profiles = ["app"]
allowed_security_capabilities = [
  "authorized_target_metadata_read",
  "approved_provider_http",
]
```

The compatible initial opt-in requires `require_sandbox=false` and zero CPU/memory
caps. If sandbox or unsupported resource enforcement is required, the check
returns `E_MCP_POLICY_UNSUPPORTED` before observation. The isolated fixed metadata
helper is not an OS sandbox. Positive wall deadlines are supported through shared
budgets. An offline-only setup can deny network and grant only
`authorized_target_metadata_read`, provided that the profile permits offline mode
and has an approved cache.

Existing denied-tools, allowed-backend, working-directory, profile and rate limits
continue to apply. Frozen grants are checked before rate admission; current path,
executable and scope identity are revalidated under the same deadline before
inventory, cache or network access. Editing the configuration file after server
startup does not grant a running server new authority; restart under the reviewed
configuration when intentionally changing permissions.

Example JSON-RPC call:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "pybun_security_check",
    "arguments": {
      "profile": "app",
      "target": "installed",
      "mode": "online",
      "fail_on": "high"
    }
  }
}
```

MCP `content[].text` contains the same typed body as CLI `detail`, with separate
policy/rate transport metadata. Unknown fields and unsupported action names are
rejected at runtime. A finding alone does not set `isError`; incomplete checks or
matched `fail_on` policies do.

## Results and exit status

| Exit | Meaning |
| --- | --- |
| 0 | Completed observation, including findings or a validated empty inventory. |
| 1 | Completed observation with a matching `--fail-on` threshold. |
| 2 | Usage or malformed request. |
| 3 | Incomplete, stale, unsupported, denied, or operational failure. Takes precedence over a threshold match. |

The operational detail status is `complete`, `partial`, or `error`. A completed
observation can contain vulnerabilities; it is not a guarantee that the project
is safe. A partial check retains available findings and threshold matches. Known
provider `database_specific.severity` labels are normalized as low, medium, high,
or critical (`MODERATE` maps to medium). Other forms, including unsupported CVSS
vectors, remain `unknown`. Unknown severity conservatively matches every requested
threshold; it never becomes low merely because evidence is missing.

The canonical full v2 wire example is
[security_check_v2.json](../tests/fixtures/security_check_v2.json). It is generated
from a controlled empty-inventory fixture through the shared assessment/result
code. Its fixture tags and clock are test inputs, not production evidence. Actual
observations include their interpreter marker environment and full target tag
profile. Four separate coverage units are mandatory:
`inventory_instances`, `advisory_records`, `finding_clusters`, and `candidate_checks`.
These count different things and must not be summed as a single scanned total.

`assessment_id` hashes normalized semantic facts; `observation_id` and payload
digests identify captured evidence. Timestamp/irrelevant-text differences do not
alone establish a new semantic assessment. Freshness, source, scope, availability,
known constraints, and incompleteness still affect what the evidence proves.
"Passes known constraints" does not establish full transitive solvability. Sparse
fix data means unavailable evidence, not "no upstream fix".

`max_output_bytes` is configured between 4,096 and 5 MiB. The shared limiter counts
escaped JSON text and reserves 2,048 bytes for transport metadata. MCP additionally
checks its final decorated wire payload; the caller-controlled JSON-RPC `id` is
excluded from the server-owned payload budget. If evidence does not fit, the result
is operational exit 3 with explicit omitted counts for all four coverage units,
plus omitted threshold matches and the total `threshold_match_count`. Consumers
must not treat the shortened result as a complete or clean scan.

## Contract verification

Schema v1 stays frozen. The v2 detail schema selects the existing backend result
or the strict security-check result and rejects unsupported assessment versions,
missing tag/marker context, merged coverage counts, unsafe remediation fields,
and claims of completed resolution/verification. The named `AssessmentContinuation`
schema does not define a future event replay cursor prematurely.

The real JSON Schema validator used in CI can also run locally in an isolated
test environment:

```sh
uv venv /tmp/pybun-schema-tests
uv pip install --python /tmp/pybun-schema-tests/bin/python \
  --index-url https://pypi.org/simple jsonschema==4.25.1 PyYAML
/tmp/pybun-schema-tests/bin/python -m unittest \
  scripts.ci.tests.test_security_check_schema -v
```

Schema acceptance checks wire shape; the CLI/MCP and provider regression suites
separately verify authorization, no startup hooks, privacy, cache/deadline bounds,
and assessment semantics. Live-provider behavior is not established by the
controlled schema fixture.
