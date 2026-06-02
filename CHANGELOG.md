# Changelog

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
