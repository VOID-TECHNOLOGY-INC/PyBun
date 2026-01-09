# Repository Guidelines

## Project Structure & Module Organization
- `src/`: Rust core (CLI, resolver, runtime, MCP, sandbox). Entry points: `src/main.rs`, modules in `src/*.rs`.
- `tests/`: Rust integration tests (snapshots under `tests/snapshots/`).
- `pybun/`: Minimal Python shim that bootstraps the signed Rust binary (`pybun/cli.py`, `bootstrap.py`, tests in `pybun/tests/`).
- `docs/`, `examples/`, `scripts/`, `schema/`: Documentation, sample code, dev scripts, and JSON schemas.
- Packaging: `Formula/` (Homebrew), `winget/` (Windows). Release metadata in `release-metadata/`.

## Build, Test, and Development Commands
- Rust build: `cargo build` (debug), `cargo build --release` (optimized).
- Test (Rust): `cargo test` (all), `cargo test <name>` (filter).
- Lint/format: `cargo clippy --all-targets --all-features -- -D warnings`, `cargo fmt -- --check`.
- Shortcuts: `make check` or `just check`; run CLI: `cargo run -- --help` or `just run -- --help`.

## Coding Style & Naming Conventions
- Rust: keep `cargo fmt` clean and zero clippy warnings. Use `snake_case` for modules/functions, `CamelCase` for types, `SCREAMING_SNAKE_CASE` for constants. Avoid `unsafe` unless justified in-code and reviewed.
- Python shim: PEP 8 (4-space indents, `snake_case`). Keep the shim small and deterministic; prefer structured JSON outputs consistent with the Rust CLI.

## Testing Guidelines
- Rust integration tests live in `tests/` and may assert structured JSON and snapshot outputs. Add focused tests for new subcommands (name files `cli_<feature>.rs`).
- Python shim tests run with `python -m unittest pybun/tests -v`.
- Aim for coverage of error paths and JSON envelopes; prefer deterministic outputs for CI.

## Commit & Pull Request Guidelines
- Use Conventional Commits: `feat(scope): ...`, `fix(ci): ...`, `docs: ...`, `chore: ...`, `test: ...`. Keep messages imperative and scoped.
- PRs must: describe changes, link issues (`Fixes #123`), note breaking changes, and include tests/docs updates. Use the template in `.github/PULL_REQUEST_TEMPLATE.md`.
- Before pushing: `cargo fmt -- --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test` (or `make check`).

## Security & Configuration Tips
- Run `cargo audit` and `cargo deny check licenses`; Python deps: `pip-audit .`. See `SECURITY.md`.
- Do not commit secrets. Release signing and packaging are automated via CI; use provided scripts in `scripts/` and follow `release.yml` if modifying.

