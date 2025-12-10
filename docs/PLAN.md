# PyBun Implementation Plan (SPECS.md → Execution)

## Planning Principles
- Ship in small, reviewable PRs with clear dependencies; prefer feature flags to unblock parallel work.
- Keep JSON/text parity from day 1 (`--format=json`) to stay AI-friendly.
- Add fast smoke/E2E checks in every milestone to guard regressions early.
- Target macOS/Linux first; keep Windows stubs/tests runnable in CI via matrix for API stability; unblock arm64 cross-build early.

## Milestones & PR Tracks
Milestones follow SPECS.md Phase roadmap. PR numbers are suggested grouping; parallelizable items marked (||).

### M0: Repo & CI Scaffold (Week 0–1)
- [DONE] PR0.1: Baseline repo (Rust workspace layout, formatting/lint config, minimal CLI stub `pybun --help`).  
  - Depends on: none.  
  - Tests: unit for arg parsing; CI: fmt + clippy + `cargo test` (minimal).
- [DONE] PR0.2: CI matrix bootstrap (macOS/Linux, Python 3.9–3.12 toolchains available) + cache for cargo.  
  - Depends on: PR0.1.  
  - Tests: noop smoke workflow to validate runners.
- [PENDING] PR0.3 ||: DX scripts (`justfile`/`Makefile`, `./scripts/dev`) + issue templates.  
  - Depends on: PR0.1.  
  - Tests: script self-check (`just lint` dry-run).
- [PENDING] PR0.4: Release/build bootstrap (cross-target builds, codesign placeholders, artifact layout for bundled CPython/data dir).  
  - Depends on: PR0.1.  
  - Tests: build workflow dry-run producing unsigned artifacts for macOS/Linux/Windows (stub).

### M1: Fast Installer (Phase 1)
- [DONE] PR1.1: Lockfile spec + serializer (`pybun.lockb` binary format, read/write, schema tests).  
  - Depends on: M0.  
  - Tests: unit for encoding/decoding; golden tests for cross-platform entries.
- [IN PROGRESS] PR1.2: Resolver core (SAT solver, index client abstraction, offline cache hooks).  
  - Current: exact-version resolver + minimum spec (`>=`) selection with highest-version pick, in-memory index; JSON fixture loading via CLI `install`. Full SAT/specifier coverage + offline cache hooks not yet implemented.  
  - Depends on: PR1.1.  
  - Tests: unit for graph resolution, conflict reporting; integration with fake index.
- [DONE] PR1.3: Installer CLI `pybun install/add/remove` with global cache + hardlink strategy.  
  - Current: `pybun install --require --index --lock` writes lockfile; `pybun add/remove` updates pyproject.toml; global cache module ready; hardlinks pending.  
  - Depends on: PR1.2.  
  - Tests: integration with temporary cache dir; 9 add/remove tests.
- [DONE] PR1.4: PEP 723 runner support (`pybun run script.py` auto env create, embedded deps).  
  - Current: `pybun run` executes Python scripts; PEP 723 metadata parsed and reported in JSON output; `-c` inline code support.  
  - Depends on: PR1.3.  
  - Tests: integration E2E executing sample script; JSON output snapshot.
- [PENDING] PR1.5: Auto env selection (`PYBUN_ENV`, `.python-version`, global env fallback).  
  - Depends on: PR1.3.  
  - Tests: integration verifying env priority; smoke E2E switching Python versions if available.
- [PENDING] PR1.6: CPython runtime management (embedded version table, download + verify missing versions, data dir layout).  
  - Depends on: PR1.3.  
  - Tests: integration simulating cache miss → download → reuse; ABI mismatch warning; offline mode failure path.
- [PENDING] PR1.7: Single-binary packaging flow (bundle CPython where allowed, otherwise bootstrap downloader) + `pybun x <pkg>` command.  
  - Depends on: PR1.6, PR0.4.  
  - Tests: smoke executing bundled binary on macOS/Linux; `pybun x cowsay` fixture; artifact size check.

### M2: Runtime & Import Optimizer (Phase 2)
- PR2.1: Rust-based module finder (replace `sys.meta_path` entry, parallel fs scan) guarded by flag.  
  - Depends on: M1.  
  - Tests: unit for path resolution; integration timing benchmark harness (CI optional).
- PR2.2: Lazy import injection MVP (config driven, allowlist/denylist, fallback to CPython).  
  - Depends on: PR2.1.  
  - Tests: integration measuring reduced import time on synthetic heavy modules; JSON diagnostics.
- PR2.3: Hot reload watcher (fs notify abstraction per OS, reload strategy) with dev profile toggle.  
  - Depends on: PR2.1.  
  - Tests: integration touching files triggers reload; smoke E2E FastAPI sample reload.
- PR2.4: Launch profiles (`--profile=dev|prod|benchmark`), logging verbosity, tracing hooks.  
  - Depends on: PR2.2, PR2.3.  
  - Tests: unit for profile parsing; integration verifying profile toggles flags.

### M3: Tester (Phase 2 tail)
- PR3.1: Test discovery engine (AST-based) + compatibility shim for pytest markers/fixtures.  
  - Depends on: M1 baseline runtime.  
  - Tests: unit on discovery; integration comparing discovered set vs pytest on sample repo.
- PR3.2: Parallel executor + shard/fail-fast; snapshot testing primitives.  
  - Depends on: PR3.1.  
  - Tests: integration for shard correctness; snapshot update flow; smoke `pybun test` on demo project.
- PR3.3: `--pytest-compat` mode warnings (JSON + text) with structured diagnostics.  
  - Depends on: PR3.2.  
  - Tests: snapshot of JSON diagnostics; E2E on plugins fixture repo.

### M4: AI/MCP & Structured Output (Phase 3)
- PR4.1: Global JSON event schema + `--format=json` for all commands.  
  - Depends on: M1 core CLI.  
  - Tests: schema validation; golden event stream for install/run/test flows.
- PR4.2: Self-healing diagnostics (dependency conflict trees, build error hints).  
  - Depends on: PR4.1, PR1.2 resolver diagnostics.  
  - Tests: integration with crafted conflicts; snapshot of suggestions.
- PR4.3: MCP server `pybun mcp serve` (RPC endpoints: resolve, install, run, test).  
  - Depends on: PR4.1.  
  - Tests: contract tests via MCP client harness; smoke E2E agent session script.
- PR4.4: Observability layer (structured logging defaults, `PYBUN_TRACE=1` tracing/trace-id propagation, redaction hooks).  
  - Depends on: PR4.1.  
  - Tests: integration ensuring trace ids emitted; redaction of env vars; log volume budget check.

### M5: Builder & Security (Phase 3/4)
- PR5.1: C/C++ build wrapper (setuptools/maturin/scikit-build isolation) + build cache.  
  - Depends on: M1 installer infra.  
  - Tests: integration building sample C extension; cache hit/miss assertions.
- PR5.2: Pre-built wheel discovery & preference; fallback to source with warnings.  
  - Depends on: PR5.1, PR1.2 resolver.  
  - Tests: integration selecting correct wheel per platform; JSON diagnostics.
- PR5.3: Security features (sig verification for downloads, SBOM emission in `pybun build`).  
  - Depends on: PR5.1.  
  - Tests: unit for signature verification; integration producing CycloneDX stub; smoke verifying tamper detection.
- PR5.4: Self-update mechanism (download, signature check, atomic swap) + `pybun doctor` bundle.  
  - Depends on: M0 CI signing hooks.  
  - Tests: integration with local file server fixture; doctor tarball content check.
- PR5.5: Sandboxed execution (`pybun run --sandbox` using seccomp/JobObject) with escape hatches.  
  - Depends on: PR2 runtime; PR5.3 security primitives.  
  - Tests: integration blocking unsafe syscalls; allowlist passthrough for network opt-in.

### M6: Release Hardening (Phase 4)
- PR6.1: Remote cache (opt-in) client skeleton; local LRU GC `pybun gc --max-size`.  
  - Depends on: M1 cache layout.  
  - Tests: integration for eviction; perf smoke on large cache dir.
- PR6.2: Workspace/monorepo support (multiple `pyproject` resolution, shared lock).  
  - Depends on: PR1.2 resolver extensions.  
  - Tests: integration on multi-package fixture; E2E install/run across workspace.
- PR6.3: Telemetry (opt-in metrics) + privacy controls; enterprise-ready configs.  
  - Depends on: PR4.1 schema.  
  - Tests: unit for redaction; integration ensuring opt-out disables emission.

## Testing & CI Strategy
- **Unit tests:** Rust crates for resolver, lockfile, module loader, test discovery; run on every PR.
- **Integration tests:** Temp workspace fixtures for install/run/test/build; run in CI on matrix (macOS, Linux, Python 3.9–3.12).
- **E2E smoke:** Per milestone, fast scenarios (<90s) invoked in CI nightly + optional PR label:
  - Install & run PEP 723 script (`pybun run examples/hello.py`).
  - Lazy import demo: load heavy dummy package under 300ms target (timing check).
  - Hot reload FastAPI demo: change file, expect single reload event.
  - `pybun test` on sample project with shards and snapshot update.
  - MCP session: resolve + install via RPC.
  - `pybun x` single-file tool exec.
  - Sandboxed `pybun run --sandbox` forbids fork/exec of disallowed binaries.
  - Self-update dry-run against local feed.
- **Performance checks:** Benchmark harness gated (not per-PR), tracked in nightly; fail on >10% regression vs baseline.
- **Artifacts:** Upload lockfile/trace logs on CI failure for debugging; code coverage trend (not gate initially).

## Checkpoints & Readiness Gates
- M1 exit: Reproducible installs with binary lock; PEP 723 runnable; CI green on macOS/Linux.
- M2 exit: Module finder + lazy import behind flag stable; hot reload demos pass smoke.
- M3 exit: `pybun test` parity on sample repo; pytest-compat warnings sane; shard/fail-fast validated.
- M4 exit: JSON schema stable; MCP server usable by scripted client; self-healing diagnostics for conflicts.
- M5 exit: C extension build cache works; SBOM generated; self-update succeeds in controlled test; sandbox mode blocks unsafe syscalls.
- M6 exit: Workspace resolution works; GC reliable; telemetry opt-out verified; Windows arm64/mac arm64 artifacts produced.

## Parallelization Notes
- PR0.3, PR1.4, PR1.5 can proceed in parallel once CLI skeleton exists.  
- Runtime (PR2.x) and Tester (PR3.x) can run concurrently after installer APIs stabilize.  
- AI/MCP work (PR4.x) can start after JSON schema foundation (PR4.1) even if runtime optimizations are behind flags.  
- Builder/security (PR5.x) mostly independent from runtime; blocked only on installer/cache foundations.  
- Release hardening (PR6.x) is parallelizable once cache + resolver APIs are stable.  
- Windows enablement tasks can trail by one milestone using shared abstractions; keep stubs/tests to avoid drift.
