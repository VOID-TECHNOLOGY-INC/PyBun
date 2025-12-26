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
- [DONE] PR3.3: `--pytest-compat` mode warnings (JSON + text) with structured diagnostics.  
  - Depends on: PR3.2.  
  - Current: `--pytest-compat` flag enables structured compatibility warnings. Warnings are collected during AST discovery and emitted as `Diagnostic` objects with level, code, message, file, line, and suggestion fields. JSON output includes `compat_warnings` array with warning details and hints. Text output displays formatted warnings with severity icons when `--verbose` is used. Warning codes: W001 (session/package fixtures), W002 (plugin decorators), I001 (parametrize info). Each warning includes a hint for resolution (e.g., "use --backend pytest").
  - Tests: 6 E2E tests (warnings in JSON, hints, structure, no-flag behavior, diagnostics envelope, parametrize info).

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
- [DONE] PR4.3b: MCP tool 実装を "Would …" から実動へ（内部コマンド呼び出し）  
  - Goal: `pybun_install/pybun_run/pybun_resolve` が CLI と同等の実処理を呼ぶ（少なくとも install/run/gc/doctor）。  
  - Notes: まず stdio のみでOK。HTTP mode は別PRで。
  - Current: `pybun_resolve` はパッケージインデックスからの依存解決を実行。`pybun_install` は依存解決→lockfile生成を実行。`pybun_run` はPythonスクリプト/インラインコードを実行し、stdout/stderr/exit_codeを返却。`pybun_doctor` は環境診断（Python, cache, project, lockfile）を実行。`pybun_gc` は既に実動。
  - Tests: 4つのE2Eテスト追加（tools/call doctor, run inline code, gc dry-run, resolve no-index）。
- PR4.3c: MCP HTTP mode（任意）  
  - Goal: `pybun mcp serve --port` を実装（現状は未実装の明示あり）。  
  - Risk: 運用/セキュリティ（bind addr, auth）を詰める必要があるので、後回しでもよい。
- [DONE] PR4.4: Observability layer (structured logging defaults, `PYBUN_TRACE=1` tracing/trace-id propagation, redaction hooks).  
  - Depends on: PR4.1.  
  - Current: Full observability via `src/schema.rs`. PYBUN_TRACE=1 enables UUID trace IDs. Event streaming with timestamps. Diagnostics array. Schema version tracking. PYBUN_LOG for log level control. Sensitive env vars not leaked in output.
  - Tests: 9 observability E2E tests (trace_id presence/absence, event timestamps, duration_ms, schema version, diagnostics, env var redaction, log level, event types).

### M5: Builder & Security (Phase 3/4)
- [DONE] PR5.0 (bootstrap): `pybun build` の “まず動く” 実装（`python -m build` の薄いラッパー + `--sbom` はスタブ出力）  
  - Goal: CLI/JSON/成果物ディレクトリの外形を固める。  
  - Notes: SBOMの本実装は PR5.3 で良いが、`--sbom` が何かを出すこと自体は早めに整えるとUXが良い。
  - Current: `pybun build` がプロジェクトの `pyproject.toml` を検出して `python -m build` を実行し、dist配下の成果物を列挙してJSON/Textで報告。`--sbom` 指定時は `dist/pybun-sbom.json` にスタブを書き出す。stdout/stderr/exit_codeをJSONに含め、Python環境情報も返す。
  - Tests: `cargo test --test cli_build`, `cargo test --test json_schema`, `cargo test`.
- [DONE] PR5.1: C/C++ build wrapper (setuptools/maturin/scikit-build isolation) + build cache.  
  - Depends on: M1 installer infra.  
  - Current: Build backend detection from `pyproject.toml` with isolation env wrapper; build cache hashes project inputs and restores/stores dist artifacts. JSON output now includes backend and cache metadata for `pybun build`.
  - Tests: `tests/cli_build.rs` cache hit/miss integration; `src/build.rs` unit tests for cache key change and dist restore.
- [DONE] PR5.2: Pre-built wheel discovery & preference; fallback to source with warnings.  
  - Depends on: PR5.1, PR1.2 resolver.  
  - Current: Installer consumes wheel metadata from the index, prefers platform-matched wheels, records selected artifacts in the lock with host platform tags, and emits warnings/diagnostics when falling back to sdist builds.
  - Tests: `tests/cli_install.rs` platform wheel selection + source fallback warning (JSON diagnostics); `cargo test`; `cargo clippy`.
- [DONE] PR5.3: Security features (sig verification for downloads, SBOM emission in `pybun build`).  
  - Depends on: PR5.1.  
  - Current: Downloader now enforces SHA-256 plus ed25519 signature verification (tampered artifacts are removed). `pybun build --sbom` emits real CycloneDX SBOMs with tool metadata and per-artifact SHA-256 hashes instead of stubs. Shared security helpers for hash/signature validation.  
  - Tests: `cargo test` (all), `cargo clippy --all-targets --all-features -D warnings`; new SBOM integration + signature verification/tamper detection tests.
- [DONE] PR5.4: Self-update mechanism (download, signature check, atomic swap) + `pybun doctor` bundle.  
  - Depends on: M0 CI signing hooks.  
  - Current: `pybun self update` with `--channel` (stable/nightly) and `--dry-run` flags. Version check logic implemented. `pybun doctor` enhanced with environment checks (Python, cache, project). JSON output with detailed check results.
  - Tests: 9 self_update E2E tests (help, version info, dry-run, channels, doctor checks).
- [DONE] PR5.5: Sandboxed execution (`pybun run --sandbox` using seccomp/JobObject) with escape hatches.  
  - Depends on: PR2 runtime; PR5.3 security primitives.  
  - Current: `pybun run --sandbox` injects a Python `sitecustomize` shim that blocks subprocess creation and socket APIs by default, with `--allow-network`/`PYBUN_SANDBOX_ALLOW_NETWORK=1` as an escape hatch. JSON output now reports sandbox policy metadata. Inline `-c` runs are also sandbox-aware.  
  - Tests: `tests/sandbox.rs` (blocks subprocess spawn, network opt-in), `cargo test`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --test '*'`.

### M6: Release Hardening (Phase 4)
- [DONE] PR6.1: Remote cache (opt-in) client skeleton; local LRU GC `pybun gc --max-size`.  
  - Depends on: M1 cache layout.  
  - Current: `pybun gc` with `--max-size` (e.g., 1G, 500M) and `--dry-run` flags. LRU eviction based on file mtime. `src/cache.rs` extended with `gc()`, `total_size()`, `parse_size()`, `format_size()`. Empty directory cleanup after GC.
  - Tests: 7 GC E2E tests (help, default gc, max-size, JSON output, freed space, size units, dry-run); 6 unit tests in cache module.
- [DONE] PR6.2: Workspace/monorepo support (multiple `pyproject` resolution, shared lock).  
  - Depends on: PR1.2 resolver extensions.  
  - Current: Added workspace detection via `[tool.pybun.workspace]` with member aggregation. `pybun install` now merges dependencies from the root project and all workspace members when executed at the workspace root.  
  - Tests: `tests/workspace.rs` (workspace install aggregating member + root deps), `cargo test`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --test '*'`.
- PR6.3: Telemetry (opt-in metrics) + privacy controls; enterprise-ready configs.  
  - Depends on: PR4.1 schema.  
  - Tests: unit for redaction; integration ensuring opt-out disables emission.
- [DONE] PR6.4: Benchmark suite (`scripts/benchmark/`)
  - Depends on: M1 core CLI.
  - Current: Full benchmark suite implemented with 8 scenarios (B1-B8). Measures dependency resolution, package installation, script execution, ad-hoc execution, module finding, lazy import, test execution, and MCP response time. Compares PyBun vs uv, pip, pipx, pytest. Supports JSON/Markdown/CSV output, dry-run mode, and report generation with baseline comparison.
  - Tests: Benchmark scripts tested with dry-run and actual execution. Results output to `scripts/benchmark/results/`.

- [DONE] PR6.5: Release artifacts as “signed, verifiable distribution” (checksums/manifest/provenance)
  - Goal: GitHub Releases を単一の正本として、ユーザー/CIが**検証可能**にインストールできる形にする（署名・チェックサム・メタデータ）。
  - Depends on: PR0.4 (release workflow), PR5.3 (sig verification primitives), PR5.4 (self update).
  - Current: Release workflow now signs artifacts via minisign (dummy key on dry-run), generates `SHA256SUMS`, `pybun-release.json` manifest, SBOM, and provenance, and uploads metadata/signature files to releases. Added release-manifest parser/selector for `pybun self update` along with scripts to generate manifest + provenance.
  - Tests: `cargo fmt`; `cargo clippy --all-targets --all-features -- -D warnings`; `CARGO_INCREMENTAL=0 cargo test`; `cargo build --release`; `PATH=$(pwd)/target/release:$PATH python3 scripts/benchmark/bench.py -s run --format markdown`.

- [DONE] PR6.6: One-liner installer (curl|sh / PowerShell) + verification-first UX
  - Goal: “初回導入” を最短にしつつ、デフォルトで検証（checksum/署名）を行う。
  - Depends on: PR6.5.
  - Current: `scripts/install.sh` と `scripts/install.ps1` を追加し、OS/Arch 自動判定→リリースマニフェスト取得→SHA256/署名検証→配置まで対応。`--version`/`--channel`/`--prefix`/`--bin-dir`/`--no-verify`/`--dry-run` と JSON dry-run 出力を実装。README をワンライナー導線に更新。
  - Tests: `tests/install_scripts.rs` (`scripts/install.sh`/`scripts/install.ps1` の `--dry-run --format=json` 検証), `cargo test --test install_scripts`.

- [DONE] PR6.7: Package-manager channels (Homebrew/Scoop/winget) + automated updates on tag
  - Goal: 企業/チーム導入（IT管理・CI）で使いやすい配布チャネルを追加し、tag リリースから自動更新する。
  - Depends on: PR6.5 (checksums/manifest), PR6.6 (install UX).
  - Implementation:
    - Homebrew tap（`pybun` formula）: `sha256` を `SHA256SUMS` から引いて埋め込み、`brew install` を第一級導線に。
    - Scoop manifest（Windowsが本格化した時点で）: asset URL + sha256 + autoupdate を設定。
    - winget パッケージ（同上）: installer URL + hash + publisher metadata。
    - Tag push 時に各リポジトリ/manifest を更新する automation（GitHub Actions）を追加。
  - Current: `scripts/release/generate_package_managers.py` で Homebrew Formula / Scoop manifest / winget manifest を生成。`Formula/pybun.rb` / `bucket/pybun.json` / `winget/pybun.yaml` をリポジトリに追加し、タグリリース時にPRで自動更新するワークフローを追加。
  - Tests: `tests/package_managers.rs`（Python unit + generator integration）を追加。CI で macOS/Linux の `brew install`（tap）を smoke、Windows runner で `winget validate` を実行。

- [DONE] PR6.8: PyPI “shim” distribution (pip/pipx entry) aligned with signed releases
  - Goal: Python ユーザーが `pipx install pybun` / `pip install pybun` で導入できる入口を用意しつつ、実体は署名付きリリース成果物を利用する。
  - Depends on: PR6.5 (manifest), PR6.6 (install logic).
  - Implementation:
    - Python パッケージ `pybun` を追加し、`pybun` コマンドは “署名付きリリースの bootstrap” を行う（OS/Arch 判定→ダウンロード→検証→実行/配置）。
    - 可能なら platform wheel にバイナリ同梱（サイズ/審査と相談）。難しければ “ダウンロード型” を基本にし、完全オフライン用は別チャネルで提供。
  - Current: `pyproject.toml` + `pybun` Python パッケージを追加し、PyPI shim がリリース manifest から対象 asset を取得→SHA256/署名検証→解凍→実行するフローを実装。`PYBUN_PYPI_MANIFEST`/`PYBUN_PYPI_CHANNEL`/`PYBUN_PYPI_NO_VERIFY`/`PYBUN_PYPI_OFFLINE` を用意し、キャッシュ済みバイナリへフォールバック可能。`pybun` エントリポイントは引数をそのまま Rust バイナリに渡す。
  - Tests: `python3 -m unittest pybun.tests.test_bootstrap`, `cargo test pypi_shim`.

- [DONE] PR6.9: PyPI 連携（Simple API/JSON index）
  - Goal: `pybun install/add` が `--index` なしで PyPI から依存解決できるようにする。
  - Depends on: PR1.2 (resolver core), PR5.2 (wheel preference).
  - Current: デフォルトで PyPI JSON API を使用する `PyPiIndex` を追加（ETag/Last-Modified キャッシュ、環境変数 `PYBUN_PYPI_BASE_URL`/`PYBUN_PYPI_CACHE_DIR` でエンドポイント・キャッシュを切替）。`--offline` でキャッシュ専用モードに入り、キャッシュが無い場合は明示的に失敗する。`pybun install` は `--index` 省略時に PyPI を選択し、ローカル JSON インデックスも従来通りサポート。
  - Tests: 新規 `tests/pypi_integration.rs` でデフォルト PyPI 解決、キャッシュを使ったオフライン再実行、キャッシュ無しオフライン失敗をモックサーバーで検証。`cargo test`, `just lint` 実行済み。

### M7: GA Launch / Release Readiness
- PR7.1: API/JSON schema freeze + compat tests
  - Goal: CLI flags/env/exit codes と JSON schema v1 を GA で凍結し、ヘルプ/JSONのスナップショットテストで後方互換を守る（`--format=json` 各コマンド、`pybun --help` diff ガード）。
  - Depends on: M4 schema完成, M5/M6 release artifacts.
  - Tests: ゴールデンテストを CI に追加（text+json）。`pybun schema check` のような自己診断を用意できると良い。
  - Implementation (Tasks):
    - [ ] `pybun schema print|check` を追加（schema v1 の出力 + 破壊的変更検知）
    - [ ] `pybun --help` / 各サブコマンド help の text snapshot を追加（diff guard）
    - [ ] 代表コマンドの JSON snapshot を追加（envelope/version/events/diagnostics を固定）
    - [ ] CI に「snapshot差分があれば失敗」を追加（GA後の互換性維持）
- PR7.2: Telemetry UX/Privacy finalize（PR6.3完了後の仕上げ）
  - Goal: デフォルト opt-in/opt-out ポリシーと UI を確定し、`pybun telemetry status|enable|disable` を提供。収集フィールドのレダクションリストと Privacy Notice を docs/README に記載。
  - Depends on: PR6.3。
  - Tests: E2E でデフォルト無送信、明示enable時のみ送信、env/flag優先順位、redaction が JSON/ログに反映されることを確認。
- PR7.3: Supportability bundle + crash report hook
  - Goal: `pybun doctor --bundle` でログ/設定/trace を収集し、`--upload`（エンドポイントは env/flag 指定）でサニタイズ済みバンドルを送信。クラッシュ時にダンプ収集の opt-in フローを追加。
  - Depends on: PR5.4 doctor, PR4.4 observability.
  - Tests: Bundle 内容のシークレットレダクション、オフライン時の graceful fallback、アップロード先モックでのE2Eを追加。
  - Implementation (Tasks):
    - [ ] `pybun doctor --bundle <path>` を実装（logs/config/trace/versions を収集）
    - [ ] バンドル内の secrets を redact（env/token/URL credential 等のルール化）
    - [ ] `pybun doctor --upload` を実装（エンドポイントは env/flag、デフォルト無送信）
    - [ ] クラッシュ時の opt-in 収集フロー（ユーザー確認→保存/送信）
- PR7.4: GA docs + release note automation
  - Goal: docs を GA 用に再編（インストール導線/Homebrew/winget/PyPI shim/手動バイナリ、Quickstart、各コマンドのJSON例、sandbox/profile/test/build/MCPの運用ガイド）。タグから CHANGELOG/release notes を自動生成し、アップグレードガイド（pre-GA→GA）を用意。
  - Depends on: M6.6–6.8 チャネル整備。
  - Tests: ドキュメントlint/リンクチェック、README のワンライナーが最新リリース manifest で成功する smoke。
  - Implementation (Tasks):
    - [ ] Quickstart（install → init → add/install → run/test/build）を追加
    - [ ] 各コマンドの `--format=json` 出力例（最小 + 失敗例）を追加
    - [ ] `--sandbox` / `--profile` / `pybun mcp serve --stdio` の運用ガイドを追加
    - [ ] pre-GA→GA のアップグレードガイド（breaking changes, migration）を追加
- PR7.5: Security/compliance sign-off
  - Goal: リリース前に `cargo audit`/`pip-audit`/license scan/SBOM 署名を CI gate にし、SLSA/provenance と minisign 鍵ローテーション手順を SECURITY.md に追加。脆弱性報告窓口/SLAs を明記（`SECURITY.md`/`SECURITY.txt`）。
  - Depends on: PR5.3, PR6.5。
  - Tests: CI で audit ジョブ必須化、リリース artifact に SBOM/provenance/署名が揃っていることを検証する smoke。
- PR7.6: デフォルト別名の配布で Bun `pybun` との衝突を回避
  - Goal: 公式で衝突回避用の別名（例: `pybun-rs`/`pybun-cli`）を全チャネルに同梱し、PATH 優先順位に依存せずに併存できるようにする。
  - Depends on: PR6.7 パッケージマネージャ導線, PR6.8 PyPI shim。
  - Implementation: install.sh/PowerShell の symlink/launcher 作成を追加、Homebrew Formula/Scoop/winget manifest に別名を登録、PyPI shim で追加 console_script を提供。README/Quickstart に別名と衝突時の案内を追記し、既存 `pybun` が Bun の場合に warning を出すオプションを検討。
  - Tests: install script dry-run で別名作成を確認、packaging テストで alias バイナリが配置されることを検証、衝突時の warning 表示が出ることを E2E で確認。
  - Implementation (Tasks):
    - [ ] 公式別名（`pybun-cli` 等）を配布物に同梱（symlink/launcher/console_script）
    - [ ] install.sh / install.ps1 / Homebrew/Scoop/winget / PyPI shim の導線を統一
    - [ ] Bun 側の `pybun` を検知した場合の警告（回避策: alias使用/優先順位）を追加
- PR7.7: CLI 進捗UI（Bun 風の途中経過表示）
  - Goal: `pybun install/add/test/build/run` などの長い処理で、解決/ダウンロード/ビルド/配置の進捗を人間向けに可視化。TTY ではスピナー/プログレスバー、非TTYや `--format=json` では抑制。
  - Depends on: PR4.1 グローバルイベントスキーマ, PR4.4 observability。
  - Implementation: JSON イベントストリームから進捗レンダラーを構成（resolve/download/build/install）。`--progress=auto|always|never` + `--no-progress` エイリアス、`PYBUN_PROGRESS` を追加。`--format=json` は UI を無効化しイベントのみ出力。
  - Tests: text 出力のゴールデン/スナップショット、`--no-progress` の抑制、TTY 判定、JSON イベントとの整合性。
  - Implementation (Tasks):
    - [ ] Event → 進捗モデル（resolve/download/build/install）のマッピングを定義
    - [ ] TTY時のみスピナー/プログレスを描画（`--progress`/`PYBUN_PROGRESS`で制御）
    - [ ] `--format=json` では UI を完全無効化（イベントのみ）
    - [ ] text出力の snapshot を追加（`--no-progress` 含む）

- PR7.8: Perceived performance polish（GA体験のキビキビ感）
  - Goal: “止まって見える/遅く感じる” を減らすため、起動/PEP723の体感を GA 基準まで引き上げる。
  - Depends on: PR-OPT6a, PR-OPT7。
  - Implementation (Tasks):
    - [ ] PR-OPT6a（PEP 723 cold を `uv run` 委譲デフォルト化）をGA候補として仕上げ
    - [ ] PR-OPT7（起動オーバーヘッド調査と改善）をGA候補として仕上げ
    - [ ] ベンチの “UX基準” を定義し、回帰チェック（nightly/label）に組み込む

### Benchmark Analysis & Optimization Roadmap

**ベンチマーク結果サマリー (2025-12-14, PR-OPT1後)**:
| シナリオ | pybun | uv | python | 差分 |
|---------|-------|-----|--------|------|
| Simple Startup | 25.6ms | 20.7ms | 21.6ms | +19% vs python |
| PEP 723 Cold | 125ms | 587ms | - | **pybunが4.7倍高速** ✅ |
| **PEP 723 Warm** | **101.6ms** | 70.5ms | - | uvより44%遅い（改善前は45倍遅かった） |
| Heavy Import | 60.7ms | 48.5ms | 56.5ms | +7% vs python |

**PR-OPT1で解決された課題**:
1. ~~**PEP 723 Warm が遅すぎる**~~ → ✅ 101.6msに改善（3104ms → 101.6ms, **約30倍高速化**）
2. ~~**venv作成が毎回発生**~~ → ✅ 依存関係ハッシュベースのキャッシュで再利用
3. **PEP 723 Cold** → ✅ 125msに改善（3529ms → 125ms, **約28倍高速化**、キャッシュが効いている）

**残る課題 (2025-12-14 Analysis)**:
1. **起動オーバーヘッド (Startup Overhead)**:
   - `pybun` (25.6ms) vs `uv` (20.7ms) → +5ms の差。
   - `src/main.rs` は軽量だが、`EventCollector` やログ初期化、`clap` のパースが影響か。
   - `PR-OPT3` で環境検出キャッシュなどを導入して短縮を狙う。
2. **PEP 723 Warm Overhead**:
   - `pybun` (101.6ms) vs `uv` (70.5ms) → +31ms の差。
   - Codebase analysis findings:
     - **Redundant I/O**: `get_cached_env` 時に毎回 `deps.json` の `last_used` を更新（書き込み）している。
     - **Process Overhead**: `pybun` プロセスの子プロセスとして Python を起動している（`wait` 待ち発生）。Unix系では `exec` でプロセス置換すべき。
3. **PEP 723 Cold Overhead (Optimization)**:
   - 現状でも高速化されたが、`pip install` を依存関係ごとにループで回している（`run_script`）。
   - これを `pip install dep1 dep2 ...` の1回呼び出しにまとめればさらに高速化可能。

- [DONE] PR-OPT1: PEP 723 venv キャッシュの実装  
  - Goal: 依存関係ハッシュに基づいてvenvをキャッシュし、再利用。warmで100ms以下を目標。
  - Approach: `hash(sorted(dependencies))` → `~/.cache/pybun/pep723-envs/{hash}/` に永続化。
  - Current: `src/pep723_cache.rs` で依存関係ハッシュベースのvenvキャッシュを実装。SHA-256ハッシュ計算、LRUベースのGC、`pybun gc`統合。環境変数 `PYBUN_PEP723_NO_CACHE=1` で従来の一時venv動作にフォールバック可能。
  - Results: **Warm startで101.6ms達成** (以前は3104ms → **約30倍高速化**)。Cold startも125msに改善（3529ms → **約28倍高速化**）。uvの70.5msより44%遅いが、改善前の45倍遅い状態から大幅改善。
  - Tests: 3つのE2Eテスト追加（cache_hit JSON出力、no-cacheモード、cleanup動作）。12のユニットテスト（ハッシュ計算、キャッシュ操作、GC）。
  - Priority: **High** (45x slowdown は致命的) → 解決済み

- PR-OPT2: PEP 723 実行フロー最適化 (New Implementation Track)
  - Goal: Warm start を 101ms -> 75ms まで短縮し、uv に肉薄する。
  - Actions:
    1. **Process Replacement**: Unix系 os (`cfg!(unix)`) では `std::os::unix::process::CommandExt::exec()` を使用してプロセスを置換し、親プロセスのオーバーヘッドを排除。
    2. **Lazy Cache Update**: `last_used` の更新頻度を下げる（例: 1時間に1回、または非同期化スキップ）ことで、Read時のWrite I/Oを削減。
    3. **Batch Install**: Cold start 時に `pip install` を1回にまとめる。
  - Status: **Done**. Investigation into remaining 46ms gap revealed it's due to Python interpreter performance (PyBun uses system Python 3.14 vs uv's managed Python 3.10), not PyBun overhead (<0.2ms). Further optimization requires managing Python versions (PR-OPT3/5).

- [DONE] PR-OPT3: uv バックエンド統合 (旧 OPT2)
  - Goal: pip の代わりに uv を使用してインストールを高速化。
  - Approach: `uv pip install` を subprocess で呼び出し。`uv` が利用可能な場合は自動検出して使用。fallback は pip。
  - Result: Cold start **243ms** (prev ~289ms). `pip install` に比べてインストール時間を短縮。Python 3.14 の高速性も寄与。
  - Tests: `env::find_uv_executable` unit test. Manual E2E benchmark.

- [DONE] PR-OPT4: 起動時間の最適化 (旧 OPT3)
  - Goal: 単純スクリプトの起動時間を python と同等（20ms以下）にする。
  - Approach: 環境検出結果のキャッシュ（`.pybun/env-cache.json`）を実装し、ディレクトリ走査をスキップ。
  - Result: Startup time **25.84ms** (prev ~38ms). Matches `uv` (25.25ms) and close to native `python` (23.46ms).
  - Tests: Verified with `bench.py B3.1`.
  - Priority: Medium

- [DONE] PR-OPT5: 並列依存解決とダウンロード (旧 OPT4)
  - Goal: 複数パッケージの解決・ダウンロードを並列化。
  - Approach: `tokio` base async resolver + `reqwest` parallel download.
  - Current: `src/resolver.rs` を非同期化しメタデータ並列取得。`src/downloader.rs` を追加し、`pybun install` 時にアーティファクトを並列ダウンロード（concurrency=10）して `~/.cache/pybun/artifacts` にキャッシュ。
  - Result: 依存解決とダウンロードが完全に非同期かつ並列化され、ネットワーク帯域を効率的に利用。
  - Tests: `tests/resolver_basic.rs` (async logic), `tests/downloader_integration.rs` (parallel logic).

- [DONE] PR-OPT6: PEP 723 キャッシュ warm パス最適化
  - **分析**: B3.2_pep723_warm で pybun (140ms) が uv (69ms) に約 2x 負けている。
  - **原因**:
    1. `update_last_used()` が cache hit 時に `deps.json` を Read+Parse+Write する同期 I/O ボトルネック。
  - **実装**:
    1. `update_last_used()` 内で `fs::metadata(path).modified()` をチェックし、直近1時間以内に更新されていればRead/Parse/Writeを完全にスキップする最適化を導入。
  - Result: Warm path **106ms** (prev 140ms). 約25%高速化。uv (75ms) との差は縮まったが、startup/import overhead等の差が残る。
  - Priority: High
- [ ] PR-OPT6a: PEP 723 cold パス高速化（uv run デフォルト化）
  - **分析**: cold で最大ボトルネックは venv 作成（~1.8s）。`uv run` に委譲すると venv 作成＋インストールをスキップでき、実測で B3.2_cold が ~3.7s → ~0.63s まで短縮（warm は ~70-100ms で横ばい）。
  - **対策**:
    1. uv が存在する環境では、PEP 723 実行をデフォルトで `uv run` に委譲（単一プロセス）。uv 不在時は従来フローにフォールバック。
    2. ベンチ (B3.2) を uv run モードでも測定し、デフォルト化による回帰が無いことを確認。
    3. ログ/JSON で実行モード（uv run / pybun-run）を明示。
  - **期待効果**: cold のオーバーヘッドを <1s に圧縮し、uv との差をサブ秒レンジに抑える。

- [ ] PR-OPT7: 起動オーバーヘッド調査と改善
  - **分析**: B3.1 (simple_startup) で pybun (27.82ms) が uv (21.03ms) より約 7ms 遅い。
  - **原因候補**:
    1. `clap` CLI パース + color-eyre 初期化コスト。
    2. `find_python_env()` のディスクアクセス（env_cache が効いてない?）。
    3. `pybun run` 経由のサブプロセス spawn オーバーヘッド。
  - **改善案**:
    1. `--release` LTO 設定の見直し（codegen-units=1, lto="fat"）。
    2. env_cache の有効性検証と TTL 調整。
    3. プロファイリング（`hyperfine --show-output` + `samply`）で実測。
  - Expected: Simple startup を 22ms 以下に。
  - Priority: Medium

- [ ] PR-OPT8: ベンチマークスクリプト改善
  - **分析**: B3.2_warm の高 StdDev (78ms) はベンチマーク手法に起因する可能性。
  - **問題**:
    1. PEP 723 スクリプトが `tempfile.TemporaryDirectory` に配置されるため、毎回パスが変わる。
    2. Warmup 後もファイルシステムキャッシュ状態がバラつく。
  - **改善案**:
    1. PEP 723 ベンチ用スクリプトを `scripts/benchmark/fixtures/pep723.py` に固定配置。
    2. Cold/Warm 測定前に `sync; echo 3 > /proc/sys/vm/drop_caches`（Linux）または `purge`（macOS）で FS キャッシュをクリア。
    3. iterations を 10 に増やし、外れ値を除外（trimmed mean）。
  - Expected: StdDev を 10ms 以下に安定化。
  - Priority: Low

- [DONE] PR-OPT9: CLI ランタイム/アロケータ最適化（uv の実装を踏襲）
  - **背景**: uv は current-thread tokio runtime + `shutdown_background()` により、起動オーバーヘッドと “終了時に待たされる” 問題を避けている（例: `ref/uv/crates/uv/src/lib.rs:2522`）。また jemalloc/mimalloc を global allocator として有効化している（例: `ref/uv/crates/uv-performance-memory-allocator/src/lib.rs`）。
  - **対策案**:
    1. `#[tokio::main]` をやめ、`tokio::runtime::Builder::new_current_thread()` で明示的に runtime を構築（必要なら別スレッド + 大きめstack）。
    2. 終了時に `runtime.shutdown_background()` を呼び、不要になったHTTPタスク等を待たない（体感改善/ハング回避）。
    3. `color_eyre::install()` をデフォルトでは抑制し、`PYBUN_TRACE=1` / `RUST_BACKTRACE=1` / `--verbose` 等でのみ有効化（起動コスト削減）。
    4. uv と同様に `jemalloc`/`mimalloc` を feature flag で導入し、リリースビルドでは既定有効化を検討。
  - Current: CLI で current-thread tokio runtime を明示構築し、終了時に `shutdown_background()` を実行。`PYBUN_TRACE`/`RUST_BACKTRACE`/`--verbose` のときのみ `color_eyre` を有効化。`performance-allocator` feature で mimalloc/jemalloc を導入し default 有効化。
  - Tests: `src/entry.rs` のユニットテストで `color_eyre` の有効化条件を検証。
  - Expected: Simple startup の数ms改善 + 終了時の待ち/ハング低減。
  - Priority: High

- [ ] PR-OPT10: PyPI メタデータ取得の戦略変更（“全バージョン事前取得”の廃止）
  - **背景**: 現状 `src/pypi.rs` は `pypi/{name}/json` の後に、全バージョンに対して `pypi/{name}/{version}/json` を並列取得し `requires_dist` を埋めている（= パッケージによってはリクエスト数が爆発）。uv は “必要な候補だけ” メタデータを取りに行く設計で、さらに wheel から `.dist-info/METADATA` をレンジリクエストで読むことで全ダウンロードを避けられる（例: `ref/uv/crates/uv-client/src/remote_metadata.rs`）。
  - **対策案**:
    1. 依存解決に必要なメタデータを **lazy fetch**（候補バージョンに対してオンデマンドに取得）へ切替。
    2. キャッシュヒット時はネットワーク/JSONパースを避ける（PR-OPT11 と連携）。
    3. 可能なら PEP 658 の dist-info metadata を優先、fallback として wheel の remote zip から METADATA 抽出（uv方式）。
  - Expected: `pybun install` / resolve のネットワーク往復と総時間を大幅削減。
  - Priority: High

- [ ] PR-OPT11: HTTP キャッシュポリシー + バイナリキャッシュ（uv の `CachePolicy`/rkyv 方式を参考）
  - **背景**: uv は HTTP キャッシュセマンティクスを `CachePolicy` として保持し、fast path では rkyv により “デシリアライズほぼ無し” で鮮度判定できる（例: `ref/uv/crates/uv-client/src/httpcache/mod.rs`, `ref/uv/crates/uv-client/src/cached_client.rs:782`）。PyBun の PyPI キャッシュは JSON pretty-print 保存のため、読み書き/パースが重い。
  - **対策案**:
    1. PyPIメタデータ/インデックスレスポンスは “raw bytes + cache policy” の単一ファイル形式で保存（JSON pretty を廃止）。
    2. `Cache-Control: max-age` / ETag / 304 revalidate を正しく扱い、オフライン時の説明可能な失敗を維持。
    3. キャッシュ読み込み・重いパースは `spawn_blocking` へ逃がし、current-thread runtime と共存できるようにする。
  - Expected: Warm run のCPU時間削減 + PyPIへの不要な再問い合わせ減。
  - Priority: Medium

- [ ] PR-OPT12: 並列フェッチの重複排除（uv の `OnceMap` 方式）
  - **背景**: uv は `OnceMap` により “同一キーのネットワーク取得は1回だけ” を保証し、並列解決時の重複リクエストを抑えている（例: `ref/uv/crates/uv-once-map/src/lib.rs:10`）。
  - **対策案**:
    1. PyPIメタデータ・wheelメタデータ・アーティファクトダウンロードに OnceMap/同等の仕組みを導入。
    2. in-memory cache は `Mutex<HashMap>` から `DashMap`/OnceMap に移行し、ロック競合を削減。
  - Expected: 解決/ダウンロードのネットワーク重複と待ち時間を削減。
  - Priority: Medium

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
