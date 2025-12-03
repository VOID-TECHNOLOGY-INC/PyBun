# PyBun (Python Bundle)

Rust-powered, single-binary toolchain for Python that fuses fast dependency install, runtime/import optimization, testing, building, and an MCP server with JSON-first output for AI agents and humans alike.

## Status
- Phase: Bootstrap (CLI skeleton + CI). Core features are stubbed; see `docs/PLAN.md` and `docs/SPECS.md`.
- Platforms: macOS/Linux target first; Windows follows. arm64/amd64 planned.

## What It Aims to Deliver
- Fast installer with binary lock (`pybun.lockb`), global cache, offline mode.
- Runtime/import optimizer: lazy imports, Rust module finder, hot reload, profiles.
- Test runner with sharding, snapshots, pytest-compat mode.
- Builder for wheels/C extensions with sandbox + cache; SBOM and signature verification.
- MCP/JSON outputs for AI agents; doctor/self-update/sandboxed execution.

## Quickstart (stub)
```bash
cargo run -- --help
cargo run -- --format=json run demo.py
```
Expect stub output for now; behavior will evolve as milestones land.

## Development
Requirements: Rust stable (`rustup`, `cargo fmt`, `cargo clippy`).

Common commands:
```bash
cargo fmt
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

## Testing & CI
- Local: `cargo test` for CLI smoke; expand TDD as features ship.
- CI: `.github/workflows/ci.yml` runs fmt + clippy + test on macOS/Ubuntu.

## Roadmap Snapshot
- M1: Installer + lockfile + PEP 723 runner + env selection.
- M2: Runtime optimizer (module finder, lazy import, hot reload).
- M3: Test runner (discovery, parallel, snapshots, pytest-compat).
- M4: JSON/MCP + self-healing diagnostics.
- M5: Builder/security (sig verify, SBOM, sandbox, self-update).
- M6: Remote cache, workspaces, telemetry opt-out.

## Contributing
Please keep PRs small and feature-flagged when possible. Prefer `--format=json` outputs for agent-friendliness. Follow TDD; add/adjust tests with behavior changes.

## License
MIT (see `docs/SPECS.md` for business model notes).
