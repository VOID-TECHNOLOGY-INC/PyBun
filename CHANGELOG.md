# Changelog

## v0.1.22

### Features
- feat(audit): expose `pybun audit` vulnerability scanning on the CLI (Issue #316) (#336)
- feat(drift): dependency drift detection via AST import analysis (Issue #248) (#258)
- feat(mcp): add `pybun_audit` (Issue #247), `pybun_test` (Issue #246), and `pybun_context` (Issue #245) tools, structured traceback diagnostics for `pybun_run` (Issue #243), and a structured audit log (#257, #256, #255, #251, #252)
- feat(benchmark): add a dedicated PyBun vs uv head-to-head benchmark suite (Issue #236) (#237)
- perf(resolver): parallelize metadata fetching (Issue #239 Phase 1) (#331)

### Fixes
- fix(pypi): document cache directory precedence (Issue #269) and self-heal legacy JSON cache decode errors (Issue #262) (#330, #296)
- fix(pep723): self-heal `last_used` cache decode failures (Issue #306), corrupt script lockfiles in the CLI run path (Issue #301), and corrupted script cache entries (Issue #299) (#329, #322, #307)
- fix(diagnostics): standardize `E_*` codes and emit a diagnostic on script exit failure (Issue #266), and force locale-neutral English in JSON diagnostics (Issue #270) (#328, #323)
- fix(doctor): detect corrupt PyPI cache entries (Issue #268) (#327)
- fix(outdated): self-heal corrupt `pybun.lockb` instead of hard-failing (Issue #325) (#326)
- fix(run): report `cache_hit=true` on PEP 723 warm runs (Issue #267), remove the `--python` flag from the uv backend to fix warm cache (Issue #238), and bypass the uv backend when a PyBun script lockfile exists (Issue #234) (#321, #240, #235)
- fix(resolver): warn on silently dropped PEP 508 extras (Issue #285) (#320)
- fix(mcp): stop `pybun_install` from reporting false success (Issue #284), and default `pybun_run` to sandboxed execution (#319, #253)
- fix(upgrade/run/lock/install): select wheels via the target venv's Python instead of `PATH` (Issue #295, #294, #293, #291) (#318, #304, #303, #292)
- fix(sandbox): preserve `subprocess.Popen` class identity when blocking (Issue #300), raise a clean denial at connect-time instead of corrupting `ssl.py` (Issue #263), and surface a warning when a credential-shaped `--allow-env` is rejected (Issue #259) (#308, #298, #277)
- fix(maintenance): scope `upgrade --dry-run` artifacts to changed packages only (Issue #261) (#297)
- fix(install): default install target no longer falls back to system Python (Issue #286), and `.python-version` bare-PATH fallback no longer bypasses the safe-install-target guard (Issue #289) (#288, #290)
- fix(bootstrap): fail closed on placeholder checksum and HTTP asset URLs (Issue #283) (#287)
- fix(cli): support multiple packages in `pybun add`/`pybun remove` (Issue #264) (#278)
- fix(init): default to a buildable package scaffold (#276)

### Refactor
- refactor: extract shared spawn/timeout/kill logic into `proc_exec` (Issue #273) (#335)
- refactor(mcp): share the optional-sandbox execution primitive (Issue #272) (#334)

### Chores
- chore(deps): trim tokio feature flags from full to minimal set (Issue #274) (#333)
- chore(deps): bump the cargo-minor-patch group, and routine updates for zip, toml, thiserror, and console (#324)
- docs: fix stale/contradictory status claims across the doc set (#309), reposition PyBun as an agent interface layer rather than a uv competitor (#241), and add subagent resume/review workflow guidance (#332, #305)

## v0.1.21

### Features
- feat(doctor): self-healing diagnostics — structured remediation plans and `doctor --fix`/`--apply` (#118, #222)

### Fixes
- fix(runtime): exclude pandas/matplotlib from the lazy-import default denylist (#136, #221)
- fix(runtime): reduce production `unwrap()` panics (#209)
- fix(sandbox): surface `E_SANDBOX_CPU_LIMIT` and unsupported resource limit warnings (#203, #205)
- fix(pypi): treat stale pre-0.1.19 bincode cache as a miss and surface PyPI cache state in `doctor`/`gc` (#202, #204)

### Refactor
- refactor(commands): extract maintenance, test execution, and module-find/lazy-import/watch/profile commands into focused modules (#186, #201, #206, #208)

### Chores
- chore(ci): add Dependabot update automation and code coverage measurement via cargo-llvm-cov (#189, #207, #210)
- chore(deps): routine dependency updates (sha2, reqwest, notify, console, dirs, tikv-jemallocator, httpmock, actions/checkout, actions/setup-python, actions/download-artifact, actions/upload-artifact, actions/attest-build-provenance, actions/attest-sbom, codecov-action, peter-evans/create-pull-request, softprops/action-gh-release, and the cargo minor/patch groups) (#211-#220, #223-#231)

## v0.1.20

### Security / Release Integrity
- configure the production minisign public key and require the matching GitHub secret for tagged releases
- republish the v0.1.19 code changes with verifiable release signatures after the incomplete v0.1.19 release attempt

## v0.1.19

### Features
- feat(schema): standardize error envelopes with stable `E_*` codes and actionable hints (#198)
- feat(watch): add a polling fallback when native file watching is unavailable (#197)
- feat(sandbox): add resource limits for timeout, memory, and CPU usage (#180)
- feat(sandbox): filter environment variables by default to prevent secret leakage (#178)
- feat(run): wire launch profiles and lazy-import injection into `pybun run` (#177)
- feat(lock): support locking project dependencies without `--script` (#176)
- feat(test): integrate and harden the native PyBun test executor with timeouts, retries, snapshots, and compatibility diagnostics (#166, #167, #174, #175)
- feat(workspace): add dependency groups, member globs, and workspace selectors (#171)

### Fixes
- fix(resolver): implement compound constraints, complete PEP 508 marker evaluation, and Python ABI-matched wheel selection (#192, #196, #161)
- fix(run): add Python-compatible `-c`/`--code`, propagate child exit codes, and warn on lock/interpreter version mismatches (#151, #173, #194, #195)
- fix(sandbox): restrict system-critical writes and block `os.posix_spawn` and the `os.spawn*` family (#150, #193)
- fix(cli): make JSON help and diagnostics consistent and actionable (#164, #165, #170)
- fix(benchmark): make benchmark execution independent of the invocation directory (#157)
- perf(module-find): eliminate redundant stat calls and scan subdirectories in parallel (#179)

### Security
- fix(security): require `rustls-webpki` 0.103.13 or newer to address four RustSec advisories (#156)

## v0.1.18

### Features
- feat(sandbox): filesystem policy, execution audit, and MCP sandbox_policy (#122)
- feat(mcp): add pybun_lint, pybun_type_check, pybun_profile, pybun_fix tools (#121)

### Fixes
- fix(resolver): support PEP 425/600 wheel tags for macOS ARM64 and manylinux (closes #144)
- fix(resolver): handle PEP 508 environment markers (fixes #123) (#127)
- fix(lock,mcp): address issue #132 and #137 (#143)
- fix(mcp): suppress stdout output in stdio mode after session end (closes #129) (#141)

### Security / Integrity
- PR-A2: enforce strict lock/hash verification (#128)

## v0.1.17

### Fixes
- fix(lazy-import): prevent RecursionError by adding output module to denylist

### Refactor
- refactor(lazy-import): improve code style and documentation

## v0.1.16

### Features
- feat(self-update): harden self-update with atomic swap and rollback support

### Fixes
- fix(ci): respect `PYBUN_PYPI_CACHE_DIR` for install artifacts

### Security
- chore(deps): update `quinn-proto` for `cargo audit`

## v0.1.15

### Fixes
- fix(test): support `pybun test <directory>` (automatically discover tests in directory)
- fix(cli): clarify active Python context in logs (GLOBAL vs LOCAL)

## v0.1.14

### Fixes
- fix: correct environment detection for venvs with only `python3` binary (no `python` symlink) (#issue-fix-env-detection)
- fix: ensure `pybun add` and `install` target the correct environment

## v0.1.7

### Fixes
- correct minisign flag and bump version to 0.1.7
- use -p for minisign public key file argument

### Docs
- update CHANGELOG.md for v0.1.6

### Other
- chore(release): update package managers for v0.1.6 (#74)

## v0.1.6

### Features
- add Open in Colab badge to notebook
- add PyBun Quick Start Colab notebook and telemetry docs (#72)

### Fixes
- update snapshot version to 0.1.6
- correct repository URLs for manifests and installers (#73)

### Docs
- improve README with Agent-First positioning (#71)

### Tests
- update snapshot for v0.1.5

### Chores
- bump version to 0.1.6

### Other
- chore(release): update package managers for v0.1.5 (#70)

## v0.1.5

- Previous release
