# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

PyBun is an agent-first Python runtime written in Rust that combines package management (pip), virtual environments (venv), test runner, and MCP server into a single binary. It's designed for both AI agents (JSON-first output) and humans, with structured error diagnostics and built-in MCP server support.

## Common Development Commands

### Building and Testing
```bash
# Build the project
cargo build
cargo build --release

# Format code
cargo fmt

# Lint (must pass with zero warnings)
cargo clippy --all-targets --all-features -- -D warnings

# Run all tests
cargo test

# Run specific test suites
cargo test cli_smoke          # CLI smoke tests
cargo test json_schema        # JSON schema validation
cargo test mcp                # MCP server tests
cargo test resolver_basic     # Dependency resolver tests
cargo test e2e_general        # E2E integration tests

# Run single test by name
cargo test test_name -- --exact

# Run benchmarks
PATH=$(pwd)/target/release:$PATH python3 scripts/benchmark/bench.py -s run --format markdown
```

### Development Scripts
```bash
# Using convenience scripts
./scripts/dev fmt     # Format code
./scripts/dev lint    # Run linter
./scripts/dev test    # Run tests

# Using Make/Just
make fmt
make lint
make test
just fmt
just lint
just test
```

### Running PyBun Locally
```bash
# Run from source (debug build)
cargo run -- --help
cargo run -- add requests
cargo run -- run script.py

# Install locally
cargo install --path .
pybun --help
```

## Architecture

### Core Components

**Main Entry (`src/main.rs`)**: Parses CLI args, sets up Tokio runtime with custom stack size for commands that need it, installs crash hooks.

**CLI Layer (`src/cli.rs`)**: Defines all commands and arguments using Clap. All commands support `--format=json` for machine-readable output.

**Commands (`src/commands.rs`)**: Main execution dispatcher (200+ KB file). Routes all CLI commands to their implementations and collects events/diagnostics for JSON output.

**Resolver (`src/resolver.rs`)**: Dependency resolution engine. Implements PEP 440 version specifiers (==, >=, >, <=, <, !=, ~=). Uses in-memory index with highest-version selection.

**MCP Server (`src/mcp.rs`)**: Model Context Protocol server for AI agent integration. Implements JSON-RPC 2.0 protocol with tools: `pybun_resolve`, `pybun_install`, `pybun_run`, `pybun_gc`, `pybun_doctor`. Runs in stdio mode (`--stdio`).

**Python Environment (`src/env.rs`, `src/env_cache.rs`)**: Detects Python installations, manages virtual environments, caches environment metadata.

**Package Index (`src/index.rs`, `src/pypi.rs`)**: Loads package indexes from JSON fixtures or PyPI. Supports offline caching via `IndexCache` and `CachedIndexLoader`.

**Lockfile (`src/lockfile.rs`)**: Binary lockfile format (`pybun.lockb`) for reproducible installs. Contains package name, version, source (wheel/sdist), and hash.

**PEP 723 Support (`src/pep723.rs`, `src/pep723_cache.rs`)**: Parses inline script metadata (`# /// script`), caches parsed metadata, auto-installs dependencies in isolated environments.

**Runtime Optimization**:
- `src/module_finder.rs`: Rust-based high-speed module search
- `src/lazy_import.rs`: Lazy import configuration and code generation
- `src/hot_reload.rs`: File watching with `notify` crate (native on macOS/Linux when `native-watch` feature enabled)

**Build System (`src/build.rs`)**: Wrapper around `python -m build` with caching via `BuildCache`.

**Test Framework**:
- `src/test_discovery.rs`: AST-based test discovery
- `src/test_executor.rs`: Parallel test execution with fail-fast and sharding
- `src/snapshot.rs`: Snapshot testing support

**Security**:
- `src/sandbox.rs`: Sandbox mode for untrusted code
- `src/security.rs`: Security utilities

**Diagnostics & Maintenance**:
- `src/support_bundle.rs`: Crash hooks and support bundle generation
- `src/telemetry.rs`: Opt-in telemetry
- `src/cache.rs`: Cache management
- `src/self_update.rs`: Self-update with signature verification (ed25519 + minisign)

### Python Wrapper (`pybun/`)

The Python package `pybun-cli` provides a bootstrap shim that downloads and executes the Rust binary. This enables installation via pip/pipx while the actual tool is the compiled Rust binary.

**`pybun/bootstrap.py`**: Detects platform target (macOS/Linux/Windows, x86_64/ARM64, glibc/musl), downloads signed release from GitHub, verifies checksums, and caches the binary.

**`pybun/cli.py`**: Entry point that invokes bootstrap to ensure binary exists, then exec's it.

### JSON Output Schema (`src/schema.rs`)

All commands support `--format=json` output with this structure:
```json
{
  "version": "1",
  "command": "pybun <subcommand>",
  "status": "ok" | "error",
  "detail": { ... },
  "events": [...],
  "diagnostics": [...]
}
```

Events track progress (CommandStart, ResolveStart, InstallComplete). Diagnostics contain structured errors with hints.

## Key Implementation Details

### Dependency Resolution

The resolver (`src/resolver.rs`) uses a greedy highest-version selection strategy. It:
1. Parses version specifiers (supports all PEP 440 operators)
2. Fetches candidate versions from index
3. Filters by version constraints
4. Selects highest compatible version
5. Resolves transitive dependencies recursively

**Index Loading**: Indexes can be loaded from JSON fixtures (`--index path/to/index.json`) or PyPI. The JSON format is a map of package names to version metadata including URLs, hashes, and dependencies.

### PEP 723 Workflow

When `pybun run script.py` is executed:
1. Parse script for PEP 723 metadata (`# /// script`)
2. Check cache (`Pep723Cache`) for existing resolved environment
3. If cache miss: resolve dependencies, create isolated venv, install packages
4. Execute script in isolated environment
5. Cache environment for subsequent runs

Environment caching key includes: dependencies, Python version, script metadata hash.

### Lockfile Format

Binary lockfile (`pybun.lockb`) using `bincode` serialization. Structure:
```rust
struct Lockfile {
    packages: Vec<Package>,
}

struct Package {
    name: String,
    version: String,
    source: PackageSource, // Wheel(url, hash) | Sdist(url, hash)
}
```

**Current Limitation**: Some lock paths use `sha256:placeholder` instead of real hashes. Full hash verification is tracked in PR-A2.

### MCP Integration

The MCP server runs over stdio and implements JSON-RPC 2.0. Tools execute PyBun commands internally and return structured results. Example:

```json
// Request
{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "pybun_run", "arguments": {"script": "hello.py"}}, "id": 1}

// Response
{"jsonrpc": "2.0", "result": {"content": [{"type": "text", "text": "..."}]}, "id": 1}
```

**Known Issue**: MCP tools have independent implementations from CLI commands, leading to behavior differences (lockfile naming, index selection). PR-A3 tracks unification.

## Feature Maturity Levels

Features are implemented in stages (see `docs/PLAN.md` and `docs/SPECS.md`):

- **stub**: CLI/schema only, no real implementation
- **preview**: Works but limited OS support, feature flags, or known issues
- **stable**: Production-ready, full compatibility, CI coverage

**Current Status** (as of v0.1.17):
- ✅ Stable: `pybun install`, `pybun add/remove`, `pybun x` (with uv), `pybun run` (PEP 723 with auto-install)
- 🟡 Preview: `pybun watch` (requires `native-watch` feature), `pybun test` (wrapper mode), Windows support
- 🔴 Stub: `pybun build` (partial), `pybun mcp serve --http` (only stdio works)

## Important Constraints

### Installation Safety
When implementing install features, ensure project isolation:
- Detect project root (`pyproject.toml`)
- Create/use `.pybun/venv` or detect existing venv
- Never install directly to system Python without explicit user intent
- PR-A7 tracks making this the default behavior

### Lockfile Integrity
- Lock generation must record real sha256 hashes, not placeholders
- `--verify` mode should validate all hashes on install
- Scripts use `<script>.lock`, projects use `pybun.lockb`

### JSON Output Consistency
- All commands must support `--format=json`
- Schema version is "1"
- Status must be "ok" or "error"
- Errors go in `diagnostics` array with `kind`, `message`, `hint`
- Progress events go in `events` array

### Cross-Platform Support
- Primary: macOS (x86_64, ARM64), Linux (x86_64 glibc/musl, ARM64 glibc/musl)
- Preview: Windows (x86_64)
- Use conditional compilation (`#[cfg(unix)]`, `#[cfg(windows)]`) when needed
- Test in CI matrix to prevent platform-specific breakage

### Performance
- Performance allocators enabled by default (`jemalloc` on Unix, `mimalloc` on Windows)
- Tokio runtime uses custom stack size (see `src/entry.rs`)
- Use parallel execution where possible (async/await, `futures::stream`)

## Testing Strategy

### Test Organization
- `tests/*.rs`: Integration and E2E tests using `assert_cmd` and `predicates`
- `tests/fixtures/`: Test data (sample projects, index JSON files)
- Inline unit tests: `#[cfg(test)] mod tests { ... }` in source files

### Key Test Suites
- **CLI Smoke Tests** (`cli_smoke.rs`, `cli_*.rs`): Verify commands execute and produce expected output
- **Resolver Tests** (`resolver_basic.rs`): Version constraint handling, conflict detection
- **JSON Schema Tests** (`json_schema.rs`): Validate all JSON output matches schema
- **MCP Tests** (`mcp.rs`): JSON-RPC protocol compliance
- **E2E Tests** (`e2e_general.rs`): Full workflow tests (install → run → test)
- **PyPI Integration** (`pypi_integration.rs`): Real package resolution (may be slower)

### Test Utilities
- `assert_cmd`: Execute CLI in tests
- `predicates`: Assert on command output
- `httpmock`: Mock HTTP servers for index/download tests
- `tempfile`: Create temporary directories for isolated test environments

### Running Tests Efficiently
```bash
# Fast feedback loop during development
cargo test --lib                    # Unit tests only
cargo test cli_smoke -- --exact     # Single integration test

# Pre-push validation
cargo test                          # All tests
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt -- --check
```

## Code Style

### Rust Conventions
- Use `cargo fmt` for formatting (enforced in CI)
- Clippy must pass with `-D warnings` (no warnings allowed)
- Prefer `color_eyre::eyre::Result` for error handling
- Use `thiserror` for custom error types
- Prefer explicit types in public APIs, use inference internally

### Error Handling
- Commands return `Result<()>` and push diagnostics to `EventCollector`
- User-facing errors should include hints: `Diagnostic::error(...).with_hint("Try: pybun install")`
- Internal errors can use `.wrap_err()` for context

### Async Patterns
- Use `async/await` for I/O-bound operations (network, file system)
- Tokio runtime configured in `src/main.rs`
- Use `futures::stream` for parallel operations
- Not all commands need async; see `entry::requires_tokio_runtime()`

## Related Documentation

- `docs/SPECS.md`: Full product specification (target state)
- `docs/PLAN.md`: Implementation plan with PR tracks and current status
- `docs/UPGRADE.md`: Breaking changes and migration guides
- `README.md`: User-facing documentation
- `CHANGELOG.md`: Version history

## Environment Variables

- `PYBUN_ENV`: Path to venv to use
- `PYBUN_PYTHON`: Path to Python binary
- `PYBUN_PROFILE`: Default profile (dev/prod/benchmark)
- `PYBUN_TRACE`: Enable trace IDs in JSON output (set to "1")
- `PYBUN_LOG`: Log level (debug/info/warn/error)
- `PYBUN_HOME`: Override cache root directory
- `PYBUN_TELEMETRY`: Override telemetry setting (0/1)

## Common Tasks

### Adding a New Command

1. Add command enum variant in `src/cli.rs` with Args struct
2. Add match arm in `src/commands.rs::execute()`
3. Implement command logic (may be in separate module)
4. Return `RenderDetail` with text summary and JSON detail
5. Add events to collector for progress tracking
6. Add diagnostics for errors with hints
7. Write integration test in `tests/cli_*.rs`
8. Add JSON schema test in `tests/json_schema.rs`
9. Update `README.md` with command documentation

### Adding MCP Tool

1. Add tool definition in `src/mcp.rs::list_tools()`
2. Add match arm in `call_tool()` with input schema validation
3. Execute underlying command (ideally reuse CLI command implementation)
4. Format result as MCP content blocks
5. Write test in `tests/mcp.rs` with JSON-RPC request/response
6. Update README MCP section

### Modifying Resolver Behavior

1. Update logic in `src/resolver.rs::resolve()`
2. Add test case in `tests/resolver_basic.rs`
3. Consider impact on lockfile format (`src/lockfile.rs`)
4. Update index format if needed (`src/index.rs`)
5. Test with real PyPI packages (`tests/pypi_integration.rs`)

### Adding Runtime Optimization

1. Implement optimization in appropriate module (`src/module_finder.rs`, `src/lazy_import.rs`, etc.)
2. Add CLI command/flag to control behavior
3. Add profile configuration in `src/profiles.rs` if relevant
4. Write benchmark in `scripts/benchmark/`
5. Add test with before/after performance comparison

## Known Issues & Future Work

See `docs/PLAN.md` Audit Follow-up Tracks for detailed tracking. Key items:

- **PR-A1**: Self-update real binary swap (download/verify/atomic replace/rollback) - ✅ DONE
- **PR-A2**: Lockfile hash integrity (eliminate `sha256:placeholder`, enforce verification)
- **PR-A3**: Unify MCP and CLI implementations (same lockfile naming, index behavior)
- **PR-A4**: Integrate native test executor (`--backend=pybun`)
- **PR-A5**: Support optional-dependencies and dependency groups
- **PR-A6**: Add polling fallback for watch when `native-watch` disabled
- **PR-A7**: Default to project-isolated environments (avoid system Python pollution)
