# Explicit security monitors and local event replay

`pybun audit monitor` registers an approved installed environment, performs one
explicit security check, and retains findings and transition events. It runs once
and exits. It does not install a daemon or scheduler, send email/webhooks/Slack,
open a PR, install/update packages, sync a lock, resolve dependencies, deploy, or
restart an application. Notifications are local text/JSON observations of committed
events. Ordinary commands do not implicitly poll monitors.

The CLI and MCP `pybun_security_monitor` use the same typed coordinator and v2
result. Existing bare `pybun audit` and its v1 output remain unchanged. The
one-shot [security-check contract](SECURITY_CHECK.md) still governs source identity,
disclosure, inventory, candidate evidence, freshness, and severity. Candidates are
observations: resolution is not checked and verification is not run.

## Operator configuration and authority

Start with the explicit operator profile in [SECURITY_CHECK.md](SECURITY_CHECK.md).
Add `monitor_state_root` to its existing authority section, rather than creating
a second conflicting table:

```toml
[security_assessment]
config_version = 1
default_profile = "app"
monitor_state_root = "/var/lib/pybun-private/security-monitors"
# Keep the existing approved profiles, providers, source policies, and limits.
```

The path is a reviewed example, not permission to create it automatically. Its
nearest existing parent must already be a private operator-owned directory with
mode 0700. Choose a root outside the project repository; the initial store profile
does not enable repository-contained state. The explicit state-write action `add`
can initialize the approved root;
loading configuration, listing an absent root, and replay do not create the root,
lock, registry, or baseline. Existing roots and state files must satisfy owner,
private-mode, regular-file, no-follow, and pinned-identity checks. Symlink swaps,
replaced roots, and revoked permissions fail closed.

The CLI requires `--security-config PATH`. The MCP server freezes the authority
and policy from its operator-selected document at startup, preferably selected
explicitly through `PYBUN_MCP_POLICY`. A persisted registration is never an
authorization grant. Every action rechecks the current approved profile, backend,
project/environment, provider/source identities, scope, and state/cache authority.
Clients cannot supply a state path, endpoint, token, interpreter, source mapping,
or arbitrary saved candidate/advisory evidence as authority.

Compatible initial MCP opt-in requires `require_sandbox=false`, CPU/memory caps
zero, approved profile/backend/working directories, and explicit capabilities:

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
  "authorized_state_read",
  "authorized_state_write",
  "authorized_target_metadata_read",
  "approved_provider_http",
]
```

All new capabilities are denied by default. Existing denied-tools, backend,
directory, profile, and rate limits continue to apply. Unsupported sandbox,
memory, or CPU enforcement returns `E_MCP_POLICY_UNSUPPORTED`; the fixed isolated
metadata helper is not an OS sandbox. Online checks also require server network
permission. Offline checks require an approved cache and make no HTTP requests.
MCP audit events for these operations remain in memory, including denials and
rate rejection; they do not enter the generic durable execution-audit log.

| Action | Capability and behavior |
| --- | --- |
| `list` | State read; returns only currently visible registrations, without hidden counts or identities. |
| `events` | State read and current per-monitor visibility; non-consuming replay. |
| `add` | State write plus current approved target/config identity; configuration only. |
| `configure` | State write, same stored profile ID, current authority, and expected revision; no scan. |
| `remove` | State write and exact immutable identity; idempotent removal. |
| `check` | State write and target metadata read; approved-provider HTTP and network permission when online. |

Configuration-only actions can revalidate paths and executable identities, but do
not enumerate installed distributions, execute the inventory helper, or contact
providers. Removing HTTP permission does not itself grant offline cache access.

For example, replace the sample immutable ID below with a returned registration
ID. Optional `after` accepts an unchanged event replay cursor; it is not a target
or profile override:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "pybun_security_monitor",
    "arguments": {
      "action": "check",
      "monitor_id": "00000000-0000-4000-8000-000000000001",
      "mode": "online",
      "timeout_ms": 30000
    }
  }
}
```

Unknown action names/fields are rejected. `list`/`add` may select a currently
granted profile; `check`/`events`/`remove` resolve the stored profile from the
immutable monitor ID. Configure's profile argument must match that stored ID.

## Register and check once

```sh
pybun --format=json audit monitor add \
  --security-config /etc/pybun/security.toml --profile app --name app

pybun --format=json audit monitor list \
  --security-config /etc/pybun/security.toml

pybun --format=json audit monitor check "$MONITOR_ID" \
  --security-config /etc/pybun/security.toml --fail-on high

pybun --format=json audit monitor events "$MONITOR_ID" \
  --security-config /etc/pybun/security.toml --after "$CURSOR"

pybun --format=json audit monitor remove "$MONITOR_ID" \
  --security-config /etc/pybun/security.toml
```

Read `MONITOR_ID` from `detail.registration.monitor_id` after add. Store it together
with the returned epoch/revision. Names are labels and can be reused; state
mutations and MCP calls address immutable IDs. A retry removing an old ID cannot
delete a successor registered under the same name. An unavailable monitor returns
a coded check/replay/configuration error without revealing a hidden registration;
an idempotent removal retry can instead complete with `removed: false`.

Registration creates no authoritative baseline. The first explicit fresh check
starts the initial baseline; it is labeled baseline observation, not newly released
patches. Offline or incomplete evidence cannot fabricate a completed clean baseline.
Current unresolved findings remain available even when there are no new events.

The installed target includes observed metadata instances absent from the lock.
Locked/system inventory adapters are not silently substituted. Updating only the
lock cannot resolve an installed-target finding. Unsupported target/layout/scope
remains operational failure rather than permission to inspect a host interpreter.

## Configure the same profile and reset safely

A client cannot rebind an existing monitor to another profile, even when that
other profile is also approved. The `--profile` argument to configure must equal
the registration's stored `config.profile_id`.

To adopt a reviewed operator change, edit that **same profile ID** in the operator
document, restart a frozen MCP server under the new document if applicable, then
explicitly configure using the last authorized revision:

```sh
pybun --format=json audit monitor configure "$MONITOR_ID" \
  --security-config /etc/pybun/security.toml \
  --profile app --expected-revision "$CONFIG_REVISION"
```

Configure compares and swaps the expected revision; a stale caller must not
overwrite a newer configuration. It starts a new epoch with a replacement baseline
pending and performs no scan. Save the returned revision/epoch, then run an explicit
check. The current operator must authorize both the stored binding and replacement
configuration; configuration stored in state cannot widen current permissions.

Comparison-domain changes, including source/provider/index policy, approved scope,
TTL/prerelease policy, or later interpreter/tag/marker identity changes, require a
new epoch before exposing replacement observations. An authorized check can also
detect a changed comparison domain and reset before establishing its baseline.
When that check adopts operator changes to the same profile's TTL or prerelease
policy, it persists those updated configuration flags with the new revision.
A freshness TTL of 0 accepts only observations with age 0; it does not grant
authority to reuse older cached observations.
Old-domain findings are not exposed under newly configured authority. Ordinary
package/version/inventory changes, per-call offline mode or narrowed request
budgets do not themselves establish a new monitor identity. Invalidated assessment
traversal restarts with a diagnostic; it does not imply an advisory was resolved.

Before the replacement baseline exists, replay may return
`E_MONITOR_BASELINE_REQUIRED`; old-epoch cursors return `E_MONITOR_CURSOR_SCOPE`.
Both carry the authorized new-scope summary/resynchronization information. A reset
is not a fix notification, and previous findings must not be called resolved simply
because their old epoch is no longer exposed. Delivering an `observation_reset`
requires explicit consumer resynchronization and returns operational exit 3, even
when `current.complete` is true. The consumer must accept the new scope/current
summary, handle the returned events, and persist and pass `replay.next_cursor`
before a subsequent complete response can return 0 again. An ordinary initial
baseline without a reset returns 0 when otherwise complete.

## Durable results, partial checks, and local prompts

The full canonical v2 example is
[security_monitor_v2.json](../tests/fixtures/security_monitor_v2.json). It was captured
from a local CLI replay fixture with current findings and retained events. Its
temporary paths, fixture advisory identities, timestamps, and random IDs are test
evidence, not observations about a production environment. The CLI envelope's
`command` is `pybun audit monitor`; `detail.action` identifies the specific action.
MCP `content[].text` contains the same typed body with separate policy/rate metadata.

These are selected fields from a complete local check result, not a second wire
schema; use the linked fixture for a full envelope:

```json
{
  "operation": "security_monitor",
  "action": "check",
  "status": "complete",
  "exit_code": 0,
  "commit_status": "committed",
  "newly_committed_count": 1,
  "newly_committed_truncated": false,
  "newly_committed_gap": false
}
```

Commit status is independent of operational completeness:

| Commit status | Meaning |
| --- | --- |
| `not_committed` | No durable commit is established for this operation. Read-only replay/list normally use this status. |
| `committed` | The mutation was published; a later response/replay error does not undo it. |
| `indeterminate` | Publication may have occurred, but durable completion was not confirmed. Do not claim rollback. |

Baseline, current findings/lineages, event IDs/counters, and assessment continuation
advance in one snapshot commit. Provider work occurs outside the short state lock;
revision/generation checks reject stale concurrent tickets. A failure after rename,
such as failed directory synchronization, is indeterminate. A lost stdout response
does not delete a committed event: replay with the previous caller-owned cursor.

The following selected fields show a real bounded local response where the commit
and current findings survived, but duplicate assessment detail was omitted:

```json
{
  "action": "check",
  "status": "partial",
  "exit_code": 3,
  "commit_status": "committed",
  "newly_committed_count": 1,
  "omitted": {
    "assessment_details": 1,
    "threshold_matches": 0,
    "assessment_omissions": null
  }
}
```

Larger truncation explicitly counts omitted registrations, current findings, newly
committed events, replay events, and assessment/threshold details. A final MCP wire
guard can nest prior omissions. Bounds apply after persistence: a shortened response
does not shorten the active baseline. If replay events are omitted, the response
does not advance their cursor; retry from the same input cursor with a reviewed
larger output cap or consume retained pages separately. Omission of duplicate
`check` detail alone does not remove events that are actually returned for delivery.

Fresh public transitions can coexist with unrelated private/unsupported packages.
Complete fresh inventory removal can resolve a finding while providers are down;
an extant package's no-longer-affected result requires complete relevant fresh
provider evidence. Missing provider data, query omission, offline/stale cache, or
a lock-only change never proves resolution or withdrawal. Historical advisory IDs
and exact candidate versions are refreshed only through current source/disclosure
grants. They do not carry saved endpoint or authentication authority.

Local event types are `baseline_observed`, `new_advisory`,
`fix_candidate_available`, `candidate_changed`, `severity_increased`,
`candidate_unavailable`, `finding_resolved`, `advisory_withdrawn`,
`check_incomplete`, `observation_reset`, and `finding_evidence_changed`.
Equal incomplete episodes coalesce; identical polls and irrelevant text/timestamp
changes do not create new alerts. Alias merges/splits preserve lineage links rather
than fabricating new-advisory/resolution pairs. `observed_at` is when PyBun observed
the event, not an upstream release date.

The nested `check` body retains its assessment version, tag/marker context, four
distinct coverage units and unverified-candidate axes. Monitor summaries separately
retain per-finding completeness and last known authoritative facts. Unknown severity
is never ranked below low; a previous known severity survives an unknown interval.

## Replay and exact cursor persistence

`EventReplayCursor` is a monitor/epoch/sequence position. It is a different named
contract from `AssessmentContinuation`; neither cursor grants authority. Origin
sequence zero means the current epoch's beginning. Each replay page returns at most
100 retained events strictly after the requested position:

- `origin_cursor`: current epoch's sequence-zero cursor.
- `resync_cursor`: position just before the earliest retained event, for explicit
  gap/reset recovery.
- `next_cursor`: position of the last **returned** event, or the prior input cursor
  when a page returns no events. It is not the high-water mark.
- `low_water_mark`, `high_water_mark`, `has_more`, and `current`: retained-log
  boundaries and the current authorized finding summary.

The complete replay example is in the canonical fixture's `detail.replay`.
Preserve cursor strings exactly; do not decode/edit/rebuild them to skip events.
Without `--after`, replay starts at the retained low-water mark. Repeating that
request repeats the same event IDs and does not generate notifications anew. For
the first call without a saved cursor, omit `--after`; do not pass an empty string.

A caller's delivery loop is:

1. Read its last durably saved cursor for this exact monitor/epoch.
2. Request `events --after CURSOR`, or pass that cursor to an explicit `check`.
3. Process returned `replay.events` in order and deduplicate by stable `event_id`.
4. Persist `replay.next_cursor` only after those returned events were successfully
   handled. Advance only to the last handled event, never directly to high-water.
5. If `has_more` is true, fetch the next page from that saved cursor. A response
   loss before cursor persistence replays the same IDs; downstream handling must
   tolerate duplicates.

`newly_committed_events` identifies events generated by this check for local prompts;
it is not the durable delivery checkpoint. `newly_committed_count`, truncation and
gap flags can exceed the displayed page. Do not merge the new-event list with the
replay page and deliver duplicates without deduplication. Text output for `events`
and `check --after` also shows replay event IDs/types and pagination information;
it does not limit delivery information to newly committed events.

Wrong monitor/epoch or future cursors return `E_MONITOR_CURSOR_SCOPE`. Expired
cursors return `E_MONITOR_CURSOR_EXPIRED`, with current summary and low-water/resync
information. Keep the old delivery checkpoint until the consumer explicitly accepts
the gap/reset and starts from the returned resynchronization position. There is no
silent skip, server-side acknowledgement, consuming read, or exactly-once external
delivery guarantee.

## Retention, corruption, and recovery

The current store caps are 100 monitors, 1,000 inventory instances, 1,000 retained
events, 90 days of history, and a 64 MiB checkpoint. Replay pages cap at 100 events.
These are store limits, not new client-settable monitor retention options. Pruning
history does not erase an active baseline, current unresolved findings, or sequence
counters. Configuration exposes existing global/profile observation deadlines and
output bounds; it does not silently enable unbounded history.

Unknown state schemas, corrupt files, missing expected snapshots, or replaced state
roots fail closed; list/replay do not silently repair them. Preserve the state and
stop the external caller's polling while the operator investigates. Do not hand-edit
checksums, delete a registry to force success, or recreate a registration by name
and treat it as the same monitor.

There is no CLI/MCP `recover` action in these six commands. The store library has
separate explicit operator-authorized corruption-recovery APIs: a corrupt snapshot
can be quarantined under expected-revision control and replaced by a new epoch;
corrupt registry recovery quarantines it and allocates a new registry identity.
These are deliberate recovery operations, not automatic behavior of check/list.
Entire registry loss requires an explicit operator recovery/re-registration decision;
orphaned snapshots and reused names do not grant identity continuity. Consumers must
resynchronize and establish the replacement baseline rather than declare old
findings resolved.

For `indeterminate` commits, inspect current authorized state/replay under the same
monitor ID and old cursor before deciding whether to repeat an operation. Retrying
must not allocate a second notification identity for an already committed event.

## Budgets, exits, and external scheduling

All actions use one absolute authorized deadline, including current path checks,
state admission, observation, finalization and persistence. Shared observation
budgeting leaves a bounded reserve for commit/replay/rendering without extending
the original deadline. Queued operations and pure preparation can be cancelled
under that deadline. Once an atomic store write has entered, the caller waits for
its terminal commit classification; it does not return while a detached write can
continue. Store mutation checks still use the original deadline. Offline/fallback
age limits and source restrictions remain those of the approved profile. Unsupported work yields explicit incomplete/error
status instead of a fabricated clean observation.

Exit 0 means a completed observation/action, even with findings. `check --fail-on`
can return 1 when a complete assessment matches the threshold. Usage is 2;
incomplete/stale/unsupported/denied/state/replay/operational failures return 3, which
takes precedence over threshold matches. Commit status still needs separate
inspection. Output caps are 4,096 bytes through 5 MiB and include escaped text and
transport reserves; the caller-supplied JSON-RPC ID is excluded from server-owned
payload accounting. A bounded response is not a complete scan merely because its
subprocess exited normally or an earlier commit succeeded.

An operator may invoke a check from their own existing cron/CI runner. This is only
an example invocation; PyBun does not install or modify that scheduler:

```sh
/usr/local/bin/pybun --format=json audit monitor check "$MONITOR_ID" \
  --security-config /etc/pybun/security.toml \
  --after "$LAST_SAVED_CURSOR" --timeout-ms 30000
```

The caller must retain the monitor ID/cursor across runs, serialize overlapping work
or handle stale-ticket retries, preserve partial/error JSON, process commit status,
deduplicate event IDs, and update its own cursor only after handling returned events.
It must not silently discard exit 3 or install/apply a candidate because an event
appeared. External delivery credentials and notification mechanisms remain outside
PyBun's monitor state and this feature's authorization.

The [store contract](MONITOR_STATE.md), schema validator tests, local provider
fixtures and CLI/MCP capture tests cover different evidence. The canonical JSON
fixture proves wire shape for its local observation; it is not live-provider or
production-release validation.
