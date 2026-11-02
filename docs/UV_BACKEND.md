# uv backend and v0.2 migration

Normal project operations use uv (`>=0.12.0,<0.13.0`) by default. Install uv
separately and put it on PATH. `PYBUN_UV` can select a specific executable.
Missing, unsupported, or failed uv produces a structured error; PyBun never
falls back to its native resolver automatically.

| PyBun operation | Backend semantics |
| --- | --- |
| `install` | `uv sync`: exact synchronization of the project environment |
| `add` / `remove` | `uv add` / `uv remove`: mutate project metadata, lock and environment |
| `lock` | `uv lock`; `--script` selects a PEP 723 script |
| `upgrade [packages]` | `uv lock --upgrade` / `--upgrade-package`: update the lock without syncing |
| project `run` | `uv sync --inexact` (updates the lock), then the prepared Python |
| PEP 723 `run` | Initial/sandboxed: lock + locked sync; otherwise `uv sync --script --inexact`, then that script's Python |

`outdated` is not delegated: it remains a native reader of `pybun.lockb`, even
when other commands use uv.

Project run always asks uv to check the lock and environment; it does not use a
PyBun freshness cache. Changes to project metadata, workspace members, Python
selection, uv configuration, and a missing environment remain uv's responsibility.
Version compatibility and workspace-root probes are retained. Lock contents and
the prepared interpreter are validated before execution and receipt publication.

Run preserves extra installed packages, as uv's run semantics do. Install
intentionally removes extras. Python execution retains PyBun's sandbox, timeout
and launch-profile optimization settings. The uv path reports lazy import
injection as disabled. Standalone scripts without project or PEP 723 metadata
continue to use the existing interpreter path.

Sandboxed runs retain explicit `uv lock` followed by `uv sync --locked --inexact`.
For sandboxed runs, environment preparation prohibits source builds and skips
project/workspace installation. When network is denied, preparation is also
offline and cannot download Python. The Python guard is installed before site
startup hooks run. The reported policy distinguishes preparation from execution;
dependency preparation is not represented as a Python sandbox.

## Lock ownership

`uv.lock` is the project execution source of truth. Existing uv projects can be
used directly; no conversion into a competing `pybun.lockb` occurs. Workspaces
use uv's workspace root and shared environment. Script locks use uv TOML in
`<script>.lock`.

Existing `pybun.lockb` files remain untouched and are not execution inputs for
the uv path. For an existing binary script lock, explicitly rename/archive it
before creating a uv script lock; PyBun refuses to overwrite it. This migration
resolves against project/script declarations, so review the resulting uv lock.

`uv export --format pylock.toml` and `uv export --format cyclonedx1.5` are the
delegated export paths for downstream auditing/provenance. Exported artifacts
are observations of the uv lock, never independent resolution inputs. PyBun's
existing audit scans the selected environment using standard-library package
metadata for uv projects, so pip is not required; drift inspects project imports.

## JSON and MCP contracts

Delegated CLI responses use envelope version `2`; `detail.contract_version`
is `2`. MCP project tools return that same detail payload. Both include backend
name/version/operation, environment fingerprint, lock source/SHA-256, effective
policy, duration, diagnostics, and a persisted receipt identifier. Receipts live
under `.pybun/receipts/<id>.json` and omit execution stdout/stderr. Invalid expected
artifacts do not produce a receipt or successful result.

MCP `tools/call` sets `result.isError: true` for policy/argument errors and
executed tools whose payload has top-level `status: "error"`. A nonzero
`exit_code` from `pybun_run`/`pybun_test`, or nonzero `failed`, `errors`, or
`timeouts` in a `pybun_test` summary, also marks a failed call. This applies to
both native payloads and v2 envelopes; the text payload is preserved. Successful
calls and dry runs omit `isError`. Nested diagnostic observations (for example,
`pybun_doctor` checks) alone do not mark a tool call as failed.

`pybun schema print --schema-version 2` prints the new schema. Schema v1 remains
frozen and is still available with the default `schema print` / `schema check`.
Backend stdout/stderr is private: fixed diagnostics protect credentials from
netrc, keyring and backend errors, and are independent of uv's text output.

MCP exposes `pybun_install`, `pybun_add`, `pybun_remove`, `pybun_lock`,
`pybun_upgrade`, and `pybun_run`. The server operator's sandbox permissions
continue to govern run; backend selection cannot disable them.

## Experimental native compatibility

Set `PYBUN_BACKEND=native` explicitly to use the legacy schema v1 dependency
commands and binary locks. The temporary JSON fixture `--index`, `--require`,
custom binary `--lock`, system installation, and legacy upgrade selectors/dry-run
belong to this compatibility mode. They produce actionable errors in uv mode.
Standalone MCP native resolution also requires this opt-in.

For private registries and index authentication, see [PRIVATE_INDEXES.md](PRIVATE_INDEXES.md).

Native fixture/compatibility tests explicitly select native. UV error-contract
fixtures and deterministic real-uv E2E tests run normally; see
[Real-backend regression tests](#real-backend-regression-tests) for the supported
uv prerequisite and the separate opt-in live-PyPI command.


### Project snapshots and native locks

`pybun_context` and `pybun://project/snapshot` read the canonical native project
lock `pybun.lockb`, including in summary mode. They report missing, corrupt, or
legacy-format locks explicitly. In native mode, the `pybun_doctor` lockfile
check applies the same canonical filename and reports `pybun.lockb` when the
lock is missing. The
obsolete MCP-only name `pybun.lock` and custom paths passed to `install --lock`
are not auto-discovered; use the canonical project filename when consuming
project snapshots or diagnosing a project. The default uv backend continues to
prefer the applicable `uv.lock`.


### Snapshot environment health

`venv_status` describes the project environment (`.pybun/venv`, `.venv`, or
`venv`, searching ancestors up to the project root). A directory with no Python
binary is `corrupt`; no project environment is `missing`. `venv_path` identifies
both healthy and broken project environments.

`python_path` and `python_source` separately describe the selected runtime.
System Python and explicit `PYBUN_PYTHON` / `PYBUN_ENV` overrides can provide a
runtime while the project environment is missing or corrupt. Overrides do not
hide project-health warnings. These fields are available in full context,
summary context, and the project snapshot resource.


### Native test outcome reports

The native test executor reads pytest report hooks through a JSON sidecar for
all executed tests. Runtime and fixture skips, XFAIL, non-strict XPASS, and
collection/setup/teardown errors retain their pytest outcomes; printed words do
not determine results. A strict XPASS is `failed` with `strict_xpass: true` and
fails the command. Missing, malformed, or contradictory reports are errors.
CLI and MCP results expose per-test outcomes and skip reasons; MCP summaries
also include `xfail`, `xpass`, and `timeouts` counts.


### Native interpreter discovery cache

Native interpreter discovery reevaluates local and ancestor `.python-version`
selectors before reusing cached system discovery. Version-selected entries are
not reused after the selector is removed. Adding, changing, or removing version
files therefore takes effect without deleting `env_cache.json`.

### Real-backend regression tests

Regular Linux/macOS test and coverage jobs install `uv==0.12.13` and execute the
real-backend tests as part of `cargo test`. For local development, install that
supported uv version and pytest, then run:

```sh
cargo test --test cli_uv_backend --test cli_private_index
```

The deterministic suite uses local wheels, local authenticated HTTP fixtures,
dependency-free scripts and workspace/path dependencies. Offline cases forbid
Python downloads and external index access. It checks CLI/MCP execution,
sandbox positive/negative controls and the package lifecycle without the
`PYBUN_E2E_NETWORK` opt-in. Fake-backend error/contract tests remain alongside it.

The separate live-PyPI lifecycle test is explicitly ignored by default. Run it
only when live network access is intended:

```sh
cargo test --test cli_uv_backend real_uv_package_lifecycle_and_existing_project_adoption -- --ignored --exact
```

### Project run preparation measurement (Issue #579)

Measured on macOS arm64 with uv 0.12.13 (Homebrew), release binaries, and
baseline `5821cc5`. Each cell is p50 / p95 in milliseconds over 15 subprocess
runs; p95 uses nearest rank (the maximum at this sample count).

| Command | Baseline cold | Updated cold | Baseline warm | Updated warm |
| --- | ---: | ---: | ---: | ---: |
| `pybun run hello.py` | 330.18 / 791.94 | 279.60 / 327.65 | 324.18 / 336.19 | 272.05 / 281.36 |
| `uv run hello.py` (control) | 43.65 / 49.91 | 40.38 / 44.07 | 38.43 / 40.02 | 35.97 / 38.95 |

To reproduce, build each revision with `cargo build --release --locked` and
copy the binaries before switching revisions. Use an empty directory outside
the repository containing this project and `hello.py` with `print('hello')`:

```toml
[project]
name = "demo"
version = "0.1.0"
dependencies = []
```

Set separate `PYBUN_HOME` and `UV_CACHE_DIR` directories for each revision,
`PYBUN_HISTORY=0`, `UV_PYTHON` to the same absolute `python3` executable, and
`UV_PYTHON_DOWNLOADS=never`. Unset `PYBUN_UV`, `PYBUN_BACKEND`,
`UV_PROJECT_ENVIRONMENT`, `UV_PROJECT`, `UV_WORKING_DIRECTORY`, and `VIRTUAL_ENV`.
Time each command using Python `time.perf_counter()` around
`subprocess.run(..., check=True)`, discarding stdout/stderr. Run the cold series
first, deleting `.venv` and `uv.lock` before each invocation. Then warm up once
and run the warm series without deleting either. Cold here means a missing
project lock and environment, not a flushed package cache; this fixture has no
external dependencies. The first baseline cold sample was a 792 ms outlier.

For a separate trace, point `PYBUN_UV` at a shell wrapper that appends `"$*"`
to a file and then executes the absolute uv binary with `"$@"`. Exclude the
wrapper from timed samples. The baseline trace was:

```text
--version
workspace --no-progress dir --offline
lock --no-progress
sync --no-progress --locked --inexact
```

The updated trace is:

```text
--version
workspace --no-progress dir --offline
sync --no-progress --inexact
```

The warm median decreases by about 52 ms, consistent with removing one
subprocess subject to the existing 50 ms process-exit polling interval. The
remaining gap to uv is still visible; the shared runner and script/tool stages
are investigated separately in Issue #580. These observations do not change
benchmark thresholds.

### Warm script and tool execution

Default uv `run` emits `env_lookup`, `env_create`, `spawn`, and `script_end`
events in the v2 JSON envelope. Their timestamps are milliseconds since command
start: lookup covers backend/interpreter discovery, creation covers environment
preparation (including reuse), and spawn marks the start of user-code execution.
The blocking backend worker records stage times and returns them to the CLI
collector after execution; these are timing observations, not live notifications.

`x` keeps the frozen v1 schema. It uses existing `custom` events with
`data.stage` set to `env_lookup` or `spawn`, plus the existing `env_create` event.
With uv available, `x` delegates preparation and execution to
`uv tool run --quiet --isolated --from <requirement> --python <selected-python>`.
The uv-managed environment is reusable across calls, isolated from the current
project, and ignores globally installed tools. The launcher preserves console
entry points, module fallback, arguments, output capture, and the tool's exit
code. Preparation failures remain `E_X_FAILED`; they do not become tool exits.
Without uv, the disposable venv/pip path remains available.

For delegated `x`, `env_create` and `spawn` mark the uv delegation boundary;
uv's internal lookup/create/execute times cannot be separated by these events.
`env_create.data.managed_by` is `uv` and its `cache_hit` is `null`. Likewise,
`detail.cache_hit` is `null`: repeated successful calls do not prove that uv
actually reused an environment. `temp_env: null` and `cleanup: false` mean no
disposable tool environment was created or removed by PyBun; uv owns its cache.

Fast subprocess probes previously paid a fixed 50ms polling interval. Timeout
polling now stays at 1ms for the first 20ms and then backs off to 50ms for
long-running children. After initial lock creation, unsandboxed script
preparation uses a single `uv sync --script --inexact`, which refreshes the lock
and environment. Existing script locks are validated before uv runs. A script
without a lock, and sandboxed preparation, retain separate lock/locked-sync steps.
Calls without a timeout wait directly for completion while pipe readers drain
stdout/stderr concurrently. Process-group timeout termination is unchanged.

The offline regression suite builds local wheels and checks warm environment
reuse, version isolation, module fallback, preparation errors, credentials,
output/exit behavior, and timestamped stages:

```sh
cargo test --test cli_warm_execution --test cli_x
cargo test --lib proc_exec::tests
```

### Warm execution measurements (Issue #580)

Measured on macOS arm64 with uv 0.12.13, release binaries, and baseline
`5821cc5`. The PEP 723 script imports `six==1.17.0`; the tool command is
`pybun --format=json x ruff==0.14.0 -- --version`. Each warm cell is p50 / p95
in milliseconds over 15 runs, with nearest-rank p95 (the maximum at this sample
count). Baseline, updated PyBun, and uv run in rotating order on each round,
after one warm-up per command, using the same working directory and cache.
History is disabled with `PYBUN_HISTORY=0`, Python downloads are disabled, and
timed warm runs have no tracing wrapper.

| Warm command | Baseline PyBun | Updated PyBun | uv control |
| --- | ---: | ---: | ---: |
| PEP 723 `run p.py` | 328.96 / 438.03 | 96.21 / 221.92 | 37.43 / 111.59 |
| `x ruff==0.14.0 -- --version` | 575.18 / 684.15 | 53.97 / 87.50 | 25.27 / 55.52 |

The controls are `uv run --script p.py` and
`uv tool run --from ruff==0.14.0 ruff --version`. The script contains:

```python
# /// script
# dependencies = ["six==1.17.0"]
# ///
import six
print(six.__version__)
```

Warm medians improve, with measurable overhead remaining relative to uv. The
PEP 723 tail is variable: the updated sample maximum is 221.92ms and the uv
maximum is 111.59ms. These small local samples do not establish that a UX ratio
threshold has been reached, and no benchmark thresholds were relaxed.

Separate cold measurements clear `UV_CACHE_DIR` and `PYBUN_HOME`, and remove
the script lock before each run. They use three runs per command, sequential
baseline/updated batches, and a `PYBUN_UV`/PATH wrapper that records actual uv
arguments before executing the same real uv binary:

| Cold command | Baseline PyBun p50 / p95 | Updated PyBun p50 / p95 |
| --- | ---: | ---: |
| PEP 723 `run p.py` | 492.68 / 957.23 | 675.23 / 1164.16 |
| `x ruff==0.14.0 -- --version` | 1746.77 / 1968.29 | 1973.66 / 2114.80 |

Cold samples include downloads and network variance; they show no cold-start
improvement and are not directly comparable to the untraced warm table.
Traces show PEP 723 calls `--version`, `lock`, `sync`, and `python find` on
initial preparation, then `--version`, `sync`, and `python find` with an existing
valid lock. The tool path changes from creating a venv and calling `uv pip
install` on every run to one `uv tool run` delegation per call. The offline
regression suite checks the script call sequence and actual tool environment
reuse independently of the timing observations.

The initial repository benchmark run (`run` and `uv_comparison` scenarios,
`scripts/benchmark/config_ci.toml`, five iterations) completed all 20 command
measurements successfully. Evaluating the unchanged eight UX rules still
failed one rule: B3.1 simple startup measured 39.69ms for PyBun versus 26.27ms
for Python, a ratio of 1.511 against a maximum of 1.5. The PEP 723 C1 warm
comparison measured 146.82ms versus 83.10ms, ratio 1.77, within its 2.0 limit.
Successful benchmark subprocesses therefore do not mean every UX criterion
passed; the initial UX result remains a failure despite the warm-path gains.
