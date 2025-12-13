# PyBun Implementation Plan (SPECS.md → Execution)

## Planning Principles
- Ship in small, reviewable PRs with clear dependencies; prefer feature flags to unblock parallel work.
- Keep JSON/text parity from day 1 (`--format=json`) to stay AI-friendly.
- Add fast smoke/E2E checks in every milestone to guard regressions early.
- Target macOS/Linux first; keep Windows stubs/tests runnable in CI via matrix for API stability; unblock arm64 cross-build early.

## Status Note (重要)
このPLANは「実装計画」中心で、各PRの項目が **"MVPの土台（stub/preview）まで含めて[DONE]"** になっている箇所があります。  
直近の実装状況（`src/commands.rs`, `src/hot_reload.rs`, `src/mcp.rs`）に照らすと、次のフォローアップが必要です（= **大きな設計変更は不要だが、実装を"本物"にする段階**）。

- **Installer/Lock**: ✅ `pybun install` は `pyproject.toml` から依存関係を読み込む通常フローに対応。`--require` と `--index` も引き続き使用可能（`--require` 指定時はpyprojectより優先）。lockfileの `wheel/hash` は placeholder が残っており、将来の `--verify`/再現性の前提が未整備。
- **Runner (PEP 723)**: ✅ dependencies を解析し、**自動インストール→隔離環境実行**を実装済み。一時venv作成→pip install→スクリプト実行→自動クリーンアップの流れ。
- **Hot Reload**: 設定・外部ウォッチャーコマンド生成はあるが、**ネイティブ監視（notify等）**は stub。
- **Tester / Builder**: `pybun test` と `pybun build` は CLI はあるが、実装は stub（not implemented yet）。
- **MCP**: `mcp serve --stdio` は動作するが、`tools/call` の tool 実行は “Would ...” のスタブ実装。HTTP mode は未実装（CLI側で明示）。

## Milestones & PR Tracks
Milestones follow SPECS.md Phase roadmap. PR numbers are suggested grouping; parallelizable items marked (||).

### M0: Repo & CI Scaffold (Week 0–1)
- [DONE] PR0.1: Baseline repo (Rust workspace layout, formatting/lint config, minimal CLI stub `pybun --help`).  
  - Depends on: none.  
  - Tests: unit for arg parsing; CI: fmt + clippy + `cargo test` (minimal).
- [DONE] PR0.2: CI matrix bootstrap (macOS/Linux, Python 3.9–3.12 toolchains available) + cache for cargo.  
  - Depends on: PR0.1.  
  - Tests: noop smoke workflow to validate runners.
- [DONE] PR0.3 ||: DX scripts (`justfile`/`Makefile`, `./scripts/dev`) + issue templates.  
  - Depends on: PR0.1.  
  - Current: `justfile`, `Makefile`, `scripts/dev` added; GitHub issue templates and PR template created.
  - Tests: script self-check (`just lint` dry-run).
- [DONE] PR0.4: Release/build bootstrap (cross-target builds, codesign placeholders, artifact layout for bundled CPython/data dir).  
  - Depends on: PR0.1.  
  - Current: `.github/workflows/release.yml` added with cross-compilation support for macOS (x86_64, ARM64), Linux (x86_64 glibc/musl, ARM64), and Windows (stub). Codesign placeholder step included. `src/paths.rs` module added for data directory layout and artifact info management.
  - Tests: build workflow dry-run producing unsigned artifacts for macOS/Linux/Windows (stub).

### M1: Fast Installer (Phase 1)
- [DONE] PR1.1: Lockfile spec + serializer (`pybun.lockb` binary format, read/write, schema tests).  
  - Depends on: M0.  
  - Tests: unit for encoding/decoding; golden tests for cross-platform entries.
- [DONE] PR1.2: Resolver core (SAT solver, index client abstraction, offline cache hooks).  
  - Current: Full version specifier support implemented (==, >=, >, <=, <, !=, ~= PEP 440 compatible release). Offline cache hooks added via `IndexCache` and `CachedIndexLoader` in `src/index.rs`. JSON fixture loading via CLI `install`. In-memory index with highest-version selection strategy.
  - Depends on: PR1.1.  
  - Tests: 13 resolver unit tests including all specifier types; 8 CLI install E2E tests; index cache unit tests.
- [DONE] PR1.3: Installer CLI `pybun install/add/remove` with global cache + hardlink strategy.  
  - Current: `pybun install --require --index --lock` writes lockfile; `pybun add/remove` updates pyproject.toml; global cache module ready; hardlinks pending.  
  - Depends on: PR1.2.  
  - Tests: integration with temporary cache dir; 9 add/remove tests.
- [DONE] PR1.4: PEP 723 runner support (`pybun run script.py` auto env create, embedded deps).  
  - Current: `pybun run` executes Python scripts; PEP 723 metadata parsed and reported in JSON output; `-c` inline code support.  
  - Depends on: PR1.3.  
  - Tests: integration E2E executing sample script; JSON output snapshot.
- [DONE] PR1.8: `pybun install` の通常フロー化（暫定 `--require/--index` からの卒業）  
  - Goal: `pyproject.toml` の dependencies / optional-deps / lock を入力にできるようにする（`--index` は実運用の設定へ）。  
  - Notes: 大きなアーキ変更は避け、まずは「pyproject→resolve→lock更新」まで。実際のwheel取得/展開は段階的に。  
  - Current: `pybun install` が `--require` なしでも `pyproject.toml` から依存関係を読み込むように実装。空の依存リストも正しく処理。`--require` 指定時はそちらを優先。
  - Tests: 7つのE2Eテスト追加（pyproject.tomlからのinstall、複数依存、空依存、pyproject未発見エラー、--require優先、JSON出力）。
- [DONE] PR1.9: PEP 723 dependencies の自動インストール（隔離環境で実行）  
  - Goal: `pybun run` が PEP723 を検出したら一時envを作り依存を入れてから実行（`--offline`/キャッシュも考慮）。  
  - Depends on: PR1.8（解決/取得の基盤がある程度必要）。
  - Current: `pybun run` がPEP 723スクリプトを検出すると、自動的に一時仮想環境を作成し、依存関係をpipでインストール後にスクリプトを実行。実行後は自動クリーンアップ。`PYBUN_PEP723_DRY_RUN=1` でテスト用ドライランモード対応。JSON出力に `temp_env` と `cleanup` フィールドを追加。
  - Tests: 4つのE2Eテスト追加（自動インストール、JSON情報表示、空依存時のenv作成スキップ、PEP723なしスクリプト）。
- [DONE] PR1.5: Auto env selection (`PYBUN_ENV`, `.python-version`, global env fallback).  
  - Depends on: PR1.3.  
  - Current: `src/env.rs` module implements full priority-based Python environment selection (PYBUN_ENV, PYBUN_PYTHON, .pybun/venv, .python-version, system PATH). Integrated with `pybun run`.
  - Tests: unit tests for venv discovery, version file parsing, pyenv integration; integration verifying env priority.
- [DONE] PR1.6: CPython runtime management (embedded version table, download + verify missing versions, data dir layout).  
  - Depends on: PR1.3.  
  - Current: `src/runtime.rs` implements full CPython runtime management with version table (3.9-3.12), python-build-standalone integration, download/verify/extract flow, ABI compatibility checking. `pybun python list/install/remove/which` commands implemented. Integration tests in `tests/runtime_management.rs`.
  - Tests: integration simulating cache miss → download → reuse; ABI mismatch warning; offline mode failure path.
- [DONE] PR1.7: Single-binary packaging flow (bundle CPython where allowed, otherwise bootstrap downloader) + `pybun x <pkg>` command.  
  - Depends on: PR1.6, PR0.4.  
  - Current: `pybun x <pkg>` command implemented with temporary virtual environment creation, package installation via pip, and automatic cleanup. Supports version specifiers (==, >=, <=, !=, ~=, >, <). Dry-run mode available for testing (PYBUN_X_DRY_RUN=1). Console script and module execution fallback.
  - Tests: 10 E2E tests for x command (package argument required, JSON output, temp environment, cleanup, version spec, passthrough args); 6 unit tests for parse_package_spec.

### M2: Runtime & Import Optimizer (Phase 2)
- [DONE] PR2.1: Rust-based module finder (replace `sys.meta_path` entry, parallel fs scan) guarded by flag.  
  - Depends on: M1.  
  - Current: `src/module_finder.rs` implements high-performance module finder with parallel fs scanning, LRU cache, namespace package support (PEP 420). `pybun module-find` command for CLI access. Supports `--scan` for directory scanning, `--benchmark` for timing info. JSON output with module type, path, search paths. Python code generation for sys.meta_path injection.
  - Tests: 14 unit tests (cache hit/miss, package/module/namespace discovery, parallel scan, config); 9 E2E tests (CLI help, find simple/nested/package, not found, scan, JSON output, benchmark).
- [DONE] PR2.2: Lazy import injection MVP (config driven, allowlist/denylist, fallback to CPython).  
  - Depends on: PR2.1.  
  - Current: `src/lazy_import.rs` implements lazy import configuration with allowlist/denylist, default denylist for core modules (sys, os, importlib, etc.). Python code generation for `sys.meta_path` injection with LazyModule proxy, LazyFinder, LazyLoader classes. `pybun lazy-import` command with `--generate`, `--check`, `--show-config`, `--allow`, `--deny`, `--log-imports`, `--no-fallback` options. Config file support (TOML).
  - Tests: 17 unit tests (config, allowlist/denylist logic, stats, serialization); 12 E2E tests (help, config, check, generate, file output).
- [DONE] PR2.3: Hot reload watcher (fs notify abstraction per OS, reload strategy) with dev profile toggle.  
  - Depends on: PR2.1.  
  - Current: `src/hot_reload.rs` implements file watcher configuration with include/exclude patterns, debouncing, and platform abstraction. `pybun watch` command with `--show-config`, `--shell-command` for external watcher generation, customizable include/exclude patterns, debounce timing. Dev profile configuration. Shell command generation for fswatch (macOS) and inotifywait (Linux).
  - Tests: 17 unit tests (config, pattern matching, debouncing, deduplication, watcher status); 12 E2E tests (help, config, target, paths, patterns, shell command generation).
- [DONE] PR2.3b: ネイティブファイル監視の実装（`notify` 等）を feature flag で追加  
  - Goal: 現状の外部ウォッチャー生成に加えて、`pybun watch` が単体で監視→再実行できる。  
  - Risk: OS差分が出るので、まずは macOS/Linux のみ、Windows はスタブ維持。  
  - Current: `notify` v7.0 を optional dependency として追加（feature flag: `native-watch`）。`HotReloadWatcher::start_native()` でネイティブファイル監視を開始。`run_native_watch_loop()` でファイル変更時にコマンドを自動再実行。FSEvent (macOS) / inotify (Linux) を使用。デバウンス、include/exclude パターンフィルタ対応。`--dry-run` フラグでテスト時のブロッキング回避。
  - Tests: 5 unit tests (native watcher start/stop, event detection, filtering); 16 E2E tests (CLI help, config, dry-run, native-watch feature detection).
- [DONE] PR2.4: Launch profiles (`--profile=dev|prod|benchmark`), logging verbosity, tracing hooks.  
  - Depends on: PR2.2, PR2.3.  
  - Current: `src/profiles.rs` implements Profile enum (Dev, Prod, Benchmark) with ProfileConfig for each. ProfileManager for loading/selecting profiles. `pybun profile` command with `--list`, `--show`, `--compare`, `-o` (export) options. Dev: hot reload, verbose logging; Prod: lazy imports, optimizations; Benchmark: tracing, timing. Environment variable detection (PYBUN_PROFILE). Python optimization flags (-O, -OO).
  - Tests: 15 unit tests (profile parsing, config values, serialization, manager); 16 E2E tests (list, show, compare, export, config values).

### M3: Tester (Phase 2 tail)
- [DONE] PR3.0 (bootstrap): `pybun test` を "まず動く" 状態へ（pytest/unittest の薄いラッパー + JSON出力）  
  - Goal: SPECSの最終形（ASTネイティブ）へ行く前に、CLI/JSON/exit-code/`--shard`/`--fail-fast` の外形を固める。  
  - Notes: "大きな設計変更を避けるための段階投入" として推奨。
  - Current: `pybun test` がpytest/unittestをバックエンドとして使用する薄いラッパーを実装。テストパス指定、`--fail-fast`(-x)、`--shard N/M`（分散テスト用）、`--pytest-compat`、`--backend pytest|unittest`、パススルー引数をサポート。`PYBUN_TEST_DRY_RUN=1` でテスト用ドライランモード対応。JSON出力に `backend`, `discovered_files`, `tests_found`, `exit_code`, `passed`, `shard` フィールドを含む。
  - Tests: 14 E2Eテスト（help表示、基本実行、JSON出力構造、fail-fast、shard形式/無効形式、pytest-compat、test discovery、unittest対応、text出力）。
- [DONE] PR3.1: Test discovery engine (AST-based) + compatibility shim for pytest markers/fixtures.  
  - Depends on: M1 baseline runtime.  
  - Current: `src/test_discovery.rs` implements Rust-native AST-based test discovery engine. Features: test function/class/method detection, pytest marker parsing (@skip, @xfail, @parametrize), fixture discovery with scope detection (function/class/module/session), fixture dependency extraction from function signatures, compatibility warnings for pytest features requiring shim. CLI enhancements: `--discover` mode for listing tests without running, `-k/--filter` for test filtering, `-j/--parallel` for parallel execution, `-v/--verbose` for detailed output. JSON output includes full test metadata, fixture info, and compat warnings.
  - Tests: 11 unit tests (pattern matching, function/class/marker/fixture parsing, async tests, unittest style, compat warnings); 25 E2E tests including 11 new tests for AST discovery (discover mode, pytest markers, fixtures, filter, verbose, class methods, async, duration reporting).
- [DONE] PR3.2: Parallel executor + shard/fail-fast; snapshot testing primitives.  
  - Depends on: PR3.1.  
  - Current: `src/test_executor.rs` implements parallel test execution with worker threads, work stealing, and configurable worker count. `src/snapshot.rs` implements snapshot testing primitives with SnapshotFile (JSON-based storage), SnapshotManager (session management), comparison/update modes, and diff generation. CLI enhancements: `--snapshot` enables snapshot testing, `--update-snapshots` updates snapshots, `--snapshot-dir` configures snapshot directory. Sharding uses deterministic distribution (sorted by name, round-robin assignment). Fail-fast stops all workers on first failure via shared atomic flag.
  - Tests: 15 unit tests (shard validation, distribution correctness, executor config, outcome serialization); 13 E2E tests (shard correctness, deterministic distribution, no overlap, parallel+shard combination, snapshot flags).
- PR3.3: `--pytest-compat` mode warnings (JSON + text) with structured diagnostics.  
  - Depends on: PR3.2.  
  - Tests: snapshot of JSON diagnostics; E2E on plugins fixture repo.

### M4: AI/MCP & Structured Output (Phase 3)
- [DONE] PR4.1: Global JSON event schema + `--format=json` for all commands.  
  - Depends on: M1 core CLI.  
  - Current: `src/schema.rs` module implements formal JSON schema with `JsonEnvelope`, `Event`, `Diagnostic` types. Event streaming with `EventCollector` for command lifecycle tracking (CommandStart, CommandEnd, ResolveStart, InstallComplete, etc.). All commands produce structured JSON with `--format=json`. Trace ID support via `PYBUN_TRACE=1`. Schema version "1" for future compatibility.
  - Tests: 19 JSON schema tests validating envelope structure, event/diagnostic fields, all command JSON output; unit tests for schema module.
- [DONE] PR4.2: Self-healing diagnostics (dependency conflict trees, build error hints).  
  - Depends on: PR4.1, PR1.2 resolver diagnostics.  
  - Current: JSON output now includes `diagnostics` collected during execution (fix: collector diagnostics were previously dropped). Added `src/self_heal.rs` to emit structured diagnostics for resolver failures: `E_RESOLVE_MISSING` (available versions + hints) and `E_RESOLVE_CONFLICT` (conflict chains/tree context). Resolver now tracks requirement provenance to build conflict chains.
  - Tests: integration tests in `tests/json_output.rs` verifying resolver errors emit structured diagnostic codes + conflict chains; conflict fixture `tests/fixtures/index_conflict.json`.
- [DONE] PR4.3: MCP server `pybun mcp serve` (RPC endpoints: resolve, install, run, test).  
  - Depends on: PR4.1.  
  - Current: `src/mcp.rs` implements MCP server with JSON-RPC protocol support. Stdio mode via `--stdio` flag. Tools: `pybun_resolve`, `pybun_install`, `pybun_run`, `pybun_gc`, `pybun_doctor`. Resources: `pybun://cache/info`, `pybun://env/info`. Full MCP protocol compliance (initialize, tools/list, tools/call, resources/list, resources/read, shutdown).
  - Tests: 5 MCP E2E tests (help, stdio mode, initialize response, tools list, JSON format); 5 unit tests in mcp module.
- PR4.3b: MCP tool 実装を “Would …” から実動へ（内部コマンド呼び出し）  
  - Goal: `pybun_install/pybun_run/pybun_resolve` が CLI と同等の実処理を呼ぶ（少なくとも install/run/gc/doctor）。  
  - Notes: まず stdio のみでOK。HTTP mode は別PRで。
- PR4.3c: MCP HTTP mode（任意）  
  - Goal: `pybun mcp serve --port` を実装（現状は未実装の明示あり）。  
  - Risk: 運用/セキュリティ（bind addr, auth）を詰める必要があるので、後回しでもよい。
- [DONE] PR4.4: Observability layer (structured logging defaults, `PYBUN_TRACE=1` tracing/trace-id propagation, redaction hooks).  
  - Depends on: PR4.1.  
  - Current: Full observability via `src/schema.rs`. PYBUN_TRACE=1 enables UUID trace IDs. Event streaming with timestamps. Diagnostics array. Schema version tracking. PYBUN_LOG for log level control. Sensitive env vars not leaked in output.
  - Tests: 9 observability E2E tests (trace_id presence/absence, event timestamps, duration_ms, schema version, diagnostics, env var redaction, log level, event types).

### M5: Builder & Security (Phase 3/4)
- PR5.0 (bootstrap): `pybun build` の “まず動く” 実装（`python -m build` の薄いラッパー + `--sbom` はスタブ出力）  
  - Goal: CLI/JSON/成果物ディレクトリの外形を固める。  
  - Notes: SBOMの本実装は PR5.3 で良いが、`--sbom` が何かを出すこと自体は早めに整えるとUXが良い。
- PR5.1: C/C++ build wrapper (setuptools/maturin/scikit-build isolation) + build cache.  
  - Depends on: M1 installer infra.  
  - Tests: integration building sample C extension; cache hit/miss assertions.
- PR5.2: Pre-built wheel discovery & preference; fallback to source with warnings.  
  - Depends on: PR5.1, PR1.2 resolver.  
  - Tests: integration selecting correct wheel per platform; JSON diagnostics.
- PR5.3: Security features (sig verification for downloads, SBOM emission in `pybun build`).  
  - Depends on: PR5.1.  
  - Tests: unit for signature verification; integration producing CycloneDX stub; smoke verifying tamper detection.
- [DONE] PR5.4: Self-update mechanism (download, signature check, atomic swap) + `pybun doctor` bundle.  
  - Depends on: M0 CI signing hooks.  
  - Current: `pybun self update` with `--channel` (stable/nightly) and `--dry-run` flags. Version check logic implemented. `pybun doctor` enhanced with environment checks (Python, cache, project). JSON output with detailed check results.
  - Tests: 9 self_update E2E tests (help, version info, dry-run, channels, doctor checks).
- PR5.5: Sandboxed execution (`pybun run --sandbox` using seccomp/JobObject) with escape hatches.  
  - Depends on: PR2 runtime; PR5.3 security primitives.  
  - Tests: integration blocking unsafe syscalls; allowlist passthrough for network opt-in.

### M6: Release Hardening (Phase 4)
- [DONE] PR6.1: Remote cache (opt-in) client skeleton; local LRU GC `pybun gc --max-size`.  
  - Depends on: M1 cache layout.  
  - Current: `pybun gc` with `--max-size` (e.g., 1G, 500M) and `--dry-run` flags. LRU eviction based on file mtime. `src/cache.rs` extended with `gc()`, `total_size()`, `parse_size()`, `format_size()`. Empty directory cleanup after GC.
  - Tests: 7 GC E2E tests (help, default gc, max-size, JSON output, freed space, size units, dry-run); 6 unit tests in cache module.
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
