# PyBun (Python Bundle) Project Context

## Overview
PyBun is an **Agent-First Python Runtime** written in Rust. It aims to replace existing tools (pip, venv, poetry, uv) with a single, high-performance binary that serves both human developers and AI agents.

**Key Philosophy:**
- **Agent-First:** All commands support `--format=json` for reliable parsing. Built-in MCP (Model Context Protocol) server.
- **Speed:** Rust-based dependency resolution and module loading.
- **All-in-One:** Bundles package management, script execution, testing, and environment management.
- **Self-Healing:** Diagnostic output includes actionable structured fixes.

## Architecture
The project consists of a **Rust Core** (performance critical) and a **Python Bootstrap** (distribution/shim).

### Core Components (`src/`)
- **CLI (`cli.rs`, `commands.rs`):** Entry point using `clap`.
- **Resolver (`resolver.rs`):** High-speed dependency resolver (SAT solver).
- **Installer (`installer.rs`, `downloader.rs`):** Package installation and global caching.
- **Runtime (`runtime.rs`, `module_finder.rs`):** Optimization layer for Python execution (lazy imports, hot reload).
- **MCP (`mcp.rs`):** Implementation of the Model Context Protocol for AI agent integration.
- **PyPI (`pypi.rs`):** Interactions with Python Package Index.

### Python Shim (`pybun/`)
- A Python package (`pybun-cli`) that acts as a bootstrapper/shim for ensuring the Rust binary is available and executed.

## Development Workflow

### Prerequisites
- Rust (stable)
- Python 3.8+

### Build & Run
The project uses `cargo` for building and `make` (or `scripts/dev`) for convenience.

- **Build:** `cargo build` (Debug) / `cargo build --release` (Release)
- **Run:** `cargo run -- <command>`
  - Example: `cargo run -- run examples/hello.py`
  - Example: `cargo run -- --format=json mcp serve --stdio`
- **Watch:** `cargo watch -x run` (requires `cargo-watch`)

### Testing (`tests/`)
Integration tests are located in `tests/` and unit tests in `src/`.

- **Run all tests:** `cargo test`
- **Run specific test:** `cargo test mcp` or `cargo test cli_smoke`
- **Run with output:** `cargo test -- --nocapture`

### Code Quality
- **Format:** `cargo fmt`
- **Lint:** `cargo clippy --all-targets --all-features -- -D warnings`
- **Dev Script:** `./scripts/dev check` (runs fmt, lint, and test)

## Directory Structure

- `src/`: Rust source code (Core logic).
- `pybun/`: Python shim package.
- `tests/`: Rust integration tests.
- `docs/`: Documentation (Specifications, Plans, Roadmaps).
  - `docs/SPECS.md`: Detailed technical specifications.
  - `docs/PLAN.md`: Implementation roadmap.
- `scripts/`: Helper scripts for installation, benchmarking, and release.
- `examples/`: Example Python scripts for testing PyBun.

## Key Concepts for Agents

1.  **JSON Output:** When debugging or verifying output, always prefer `--format=json`.
2.  **MCP:** The project itself *is* an MCP server. Logic for this is in `src/mcp.rs`.
3.  **Sandbox:** The `--sandbox` flag isolates execution. Relevant logic is in `src/sandbox.rs`.
4.  **Diagnostics:** Error handling is structured. Look for `diagnostics` arrays in JSON responses.

## Current Status (as of Jan 2026)
- **Implemented:** Installer (M1), Runtime/Hot Reload (M2), JSON/MCP Basics (M4).
- **In Progress:** Test Runner (M3), Remote Cache (M6).
- **See:** `docs/PLAN.md` for the active roadmap.
