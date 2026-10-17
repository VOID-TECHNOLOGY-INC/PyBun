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
| project `run` | `uv lock`, then `uv sync --locked --inexact`, then the prepared Python |
| PEP 723 `run` | `uv lock --script`, `uv sync --script --locked --inexact`, then that script's Python |

Run preserves extra installed packages, as uv's run semantics do. Install
intentionally removes extras. Python execution retains PyBun's sandbox, timeout
and launch-profile optimization settings. The uv path reports lazy import
injection as disabled. Standalone scripts without project or PEP 723 metadata
continue to use the existing interpreter path.

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

Native fixture/compatibility tests explicitly select native; uv contract tests
select uv and use hermetic fake executables. Network E2E can be enabled with
`PYBUN_E2E_NETWORK=1 cargo test --test cli_uv_backend`.


### Project snapshots and native locks

`pybun_context` and `pybun://project/snapshot` read the canonical native project
lock `pybun.lockb`, including in summary mode. They report missing, corrupt, or
legacy-format locks explicitly. The obsolete MCP-only name `pybun.lock` and
custom paths passed to `install --lock` are not auto-discovered; use the canonical
project filename when consuming project snapshots. The default uv backend
continues to prefer the applicable `uv.lock`.


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
