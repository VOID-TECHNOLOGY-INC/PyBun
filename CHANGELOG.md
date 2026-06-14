# Changelog

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
