# PyBun Agent Guide

This doc is for AI coding agents (Claude Code, Cursor, Copilot Workspace, etc.) working in this repo. It summarizes capabilities, guardrails, and common workflows.

## Ground Rules
- Prefer deterministic output: use `--format=json` wherever supported; include `--verbose` only when needed.
- Never mutate files outside the repo unless explicitly instructed.
- Keep edits small and reversible; avoid destructive commands (`git reset --hard`, `rm -rf`).
- Use cache-aware flags to avoid network when not required (`--offline` if set; respect mirrors).
- Surface diagnostics, not just errors: return conflict trees, missing deps, and suggested fixes in JSON if possible.

## Core Commands (planned)
- `pybun install|add|remove`: Resolve deps using binary lock `pybun.lockb` and global cache (hardlinks). Prefer `--format=json`.
- `pybun run <script.py>`: Executes with auto env selection and import optimizations; PEP 723 supported.
- `pybun x <pkg>`: One-off tool execution without prior install.
- `pybun test`: Fast test runner with sharding and snapshot support; `--pytest-compat` for compatibility warnings.
- `pybun build`: Build artifacts; emits SBOM when enabled.
- `pybun doctor`: Collects diagnostics bundle (logs, traces).
- `pybun mcp serve`: MCP server for programmatic control (resolve/install/run/test).
- `pybun self update`: Signed self-update flow (guarded).
- `pybun run --sandbox`: Seccomp/JobObject sandbox (restricted syscalls; opt-in network).

## JSON Schema Expectations
All commands expose `--format=json`. Common envelope:
```json
{
  "version": "1",
  "command": "pybun run script.py",
  "status": "ok|error",
  "duration_ms": 123,
  "events": [],
  "diagnostics": [],
  "trace_id": "optional"
}
```
- `events`: time-ordered steps (resolve, download, build, test_case, reload).
- `diagnostics`: structured issues with `kind`, `message`, `hint`, and optional `tree` for conflicts.

## Environment Conventions
- Data dir: `${PYBUN_HOME:-~/.cache/pybun}` with `packages/`, `envs/`, `build/`, `logs/`.
- Python selection: `PYBUN_ENV` > local `.pybun/venv` > global shared env; `.python-version` respected.
- Offline mode: `--offline` avoids network; fails fast on missing cache.
- Profiles: `--profile=dev|prod|benchmark` toggles hot reload, logging, import optimization.

## Agent Workflows
- **Install & run**: `pybun add <pkg> && pybun run app.py --format=json`.
- **PEP 723**: `pybun run script.py --format=json` (auto env + deps).
- **Conflict triage**: `pybun install --format=json` to get conflict tree; suggest `pybun add pkg==x.y`.
- **Hot reload dev loop**: `pybun run app.py --profile=dev` and watch `events` for reloads.
- **Testing**: `pybun test --format=json --shard 1/2 --fail-fast`; include snapshots when prompted.
- **Sandboxed exec**: `pybun run --sandbox script.py` when untrusted code; expect blocked syscalls.
- **MCP**: start `pybun mcp serve --port 9999`; use RPC for resolve/install/run/test.

## Safety & Security
- Verify signatures automatically on downloads; do not bypass unless instructed.
- Sandboxed mode should be default for untrusted inputs; network opt-in only.
- Redact secrets in logs (`--redact` planned); avoid echoing env vars.
- Prefer pre-built wheels; fall back to source build with warnings.

## Logs, Traces, and Artifacts
- Set `PYBUN_TRACE=1` to include trace IDs; submit `logs/` and `trace.jsonl` in bug reports.
- On CI failure, upload lockfile and trace logs to artifacts for debugging.

## E2E Smoke Checklist (fast)
- `pybun run examples/hello.py --format=json`
- `pybun add requests && pybun run -c "import requests; print(requests.__version__)" --format=json`
- `pybun test --format=json --fail-fast`
- `pybun x cowsay --format=json` (or another small tool)
- `pybun run --sandbox examples/hello.py --format=json`
- MCP roundtrip: start server, resolve + install via RPC.

## Known Limits (to monitor)
- Windows support trails macOS/Linux by one milestone; keep stubs/tests green.
- Performance targets: cold start 10x CPython baseline; lazy-import heavy modules under ~300ms; monitor nightly benchmarks.
- Large C-extension builds may require toolchain presence; prefer pre-built wheel selection.
