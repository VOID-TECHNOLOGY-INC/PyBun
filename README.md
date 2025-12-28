# PyBun (Python Bundle)

A Rust-based single-binary Python toolchain. Integrates fast dependency installation, runtime/import optimization, testing, build capabilities, and AI agent-friendly JSON output.

## Status
- Current: Implementation of M1 (Fast Installer), M2 (Runtime Optimization), and M4 (MCP/JSON) is in progress (**stable/preview/stub mixed**)
- Platforms: macOS/Linux (arm64/amd64), Windows (preview)

※ For feature maturity (stub/preview/stable) and phased rollout policy, see `docs/SPECS.md`.

## Installation

Installers default to the latest stable release manifest (signatures + `release_notes`). Pin a specific manifest with `PYBUN_INSTALL_MANIFEST` when running in CI or offline builds.

```bash
# Homebrew (macOS / Linux)
brew tap pybun/pybun https://github.com/pybun/pybun
brew install pybun

# macOS / Linux (one-liner installer)
curl -LsSf https://raw.githubusercontent.com/pybun/pybun/main/scripts/install.sh | sh

# Nightly channel
curl -LsSf https://raw.githubusercontent.com/pybun/pybun/main/scripts/install.sh | sh -s -- --channel nightly

# Custom prefix
curl -LsSf https://raw.githubusercontent.com/pybun/pybun/main/scripts/install.sh | sh -s -- --prefix ~/.local
```

```powershell
# Windows (Scoop)
scoop bucket add pybun https://github.com/pybun/pybun
scoop install pybun

# Windows (winget)
winget install PyBun.PyBun

# Windows (PowerShell installer)
irm https://raw.githubusercontent.com/pybun/pybun/main/scripts/install.ps1 | iex

# With options
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/pybun/pybun/main/scripts/install.ps1))) -Channel nightly -Prefix "$env:LOCALAPPDATA\pybun"
```

```bash
# PyPI shim (pipx / pip)
pipx install pybun
# or
pip install --user pybun
```
The PyPI shim downloads and verifies the signed release binary on first run.

```bash
# Development (from source)
cargo install --path .
```

## GA Quickstart

1) Install the stable build with a pinned manifest (includes signatures + release notes):
```bash
export PYBUN_INSTALL_MANIFEST="https://github.com/pybun/pybun/releases/latest/download/pybun-release.json"
curl -LsSf https://raw.githubusercontent.com/pybun/pybun/main/scripts/install.sh | sh
# Windows (PowerShell)
irm https://raw.githubusercontent.com/pybun/pybun/main/scripts/install.ps1 | iex
```
`--format=json` on the installer surfaces the manifest, chosen asset, and `release_notes` attachment for CI logs.

2) Initialize a project (pyproject + lock):
```bash
cat > pyproject.toml <<'EOF'
[project]
name = "hello-pybun"
version = "0.1.0"
dependencies = ["requests>=2.31"]
EOF

pybun install --require requests==2.31.0 --lock pybun.lockb
```

3) Add or resolve dependencies:
```bash
pybun add httpx
pybun install --index fixtures/index.json
```

4) Run / test / build with JSON for automation:
```bash
pybun --format=json run -c -- "print('Hello, PyBun!')"      # add --sandbox for untrusted code
pybun --format=json test --fail-fast
pybun --format=json build
```

5) Self-update and verify release metadata:
```bash
pybun --format=json self update --channel stable --dry-run
```

## Command Reference

### Package Management

```bash
# Install dependencies (generates lockfile)
pybun install --require requests==2.31.0 --index fixtures/index.json

# Add a package (updates pyproject.toml)
pybun add requests

# Remove a package
pybun remove requests
```

### Script Execution

```bash
# Run a Python script
pybun run script.py

# Run with arguments
pybun run script.py -- arg1 arg2

# Run inline code
pybun run -c -- "import sys; print(sys.version)"

# Run with profile
pybun run --profile=prod script.py
```

PEP 723 inline metadata is also supported:
```python
# /// script
# requires-python = ">=3.11"
# dependencies = ["requests>=2.28"]
# ///
import requests
```
※ Currently, **metadata parsing and display are the main features (preview)**, with auto-install and isolated environment execution planned for phased rollout (see `docs/PLAN.md` for details).

### Ad-hoc Execution (`pybun x`)

Install a package in a temporary environment and execute it (Python version of `npx`):

```bash
# Temporarily install and run cowsay
pybun x cowsay

# Specify version
pybun x cowsay==6.1

# With arguments
pybun x black -- --check .
```

### Python Version Management

```bash
# Show installed versions
pybun python list

# Show all available versions
pybun python list --all

# Install Python
pybun python install 3.12

# Remove Python
pybun python remove 3.12

# Show Python path
pybun python which
pybun python which 3.11
```

### Runtime Optimization

#### Module Finder

Rust-based high-speed module search:

```bash
# Find a module
pybun module-find os.path

# Scan a directory for all modules
pybun module-find --scan -p ./src

# With benchmark
pybun module-find --benchmark os.path
```

#### Lazy Import

```bash
# Show configuration
pybun lazy-import --show-config

# Check module decision
pybun lazy-import --check numpy

# Generate Python code
pybun lazy-import --generate -o lazy_setup.py

# Specify allow/deny lists
pybun lazy-import --allow mymodule --deny debug_tools --generate
```

#### File Watch (Development Mode)

```bash
# Watch for file changes and re-run (currently preview)
# Native watching is planned for phased rollout. For now, use --shell-command (external watcher).
pybun watch main.py

# Watch a specific directory
pybun watch main.py -p src

# Show configuration
pybun watch --show-config

# Generate shell command for external watcher
pybun watch --shell-command main.py
```

### Profile Management

```bash
# Show available profiles
pybun profile --list

# Show profile settings
pybun profile dev --show

# Compare profiles
pybun profile dev --compare prod

# Export profile
pybun profile prod -o prod-config.toml
```

Profiles:
- `dev`: Hot reload enabled, verbose logging
- `prod`: Lazy imports enabled, optimizations
- `benchmark`: Tracing and timing measurement

### MCP Server

MCP server for AI agents:

```bash
# Start in stdio mode
pybun mcp serve --stdio
```

Tools: `pybun_resolve`, `pybun_install`, `pybun_run`, `pybun_gc`, `pybun_doctor`  
Resources: `pybun://cache/info`, `pybun://env/info`

※ Currently **`pybun_gc`, `pybun_doctor`, `pybun_run`, `pybun_resolve`, and resources are operational**. `pybun_install` generates lockfiles via resolution. HTTP mode is not yet implemented.

### Diagnostics & Maintenance

```bash
# Environment diagnostics
pybun doctor
pybun doctor --verbose

# Cache garbage collection
pybun gc
pybun gc --max-size 1G
pybun gc --dry-run

# Self-update check
pybun self update --dry-run
pybun self update --channel nightly
```

## Sandbox usage

Use the sandbox for untrusted scripts or PEP 723 snippets:
```bash
pybun --format=json run --sandbox examples/hello.py
pybun --format=json run --sandbox --allow-network -c "print('net ok')"
```
The sandbox isolates file and network access; add `--allow-network` only when required. Combine with `--profile=prod` for production-like runs.

## Profiles

Profiles tune defaults for performance vs. development ergonomics:
- `dev` (default): hot reload enabled, verbose logging.
- `prod`: lazy imports and optimizations enabled, quieter output.
- `benchmark`: stable timing/logging for reproducible benchmarks.

Examples:
```bash
pybun profile --list
pybun run --profile=prod app.py
pybun test --profile=benchmark --format=json
```

## MCP server (stdio)

Operate PyBun as an MCP server for agents/IDEs:
```bash
pybun mcp serve --stdio
pybun --format=json mcp serve --stdio  # JSON envelope for tooling
```
Tools: `pybun_resolve`, `pybun_install`, `pybun_run`, `pybun_gc`, `pybun_doctor`. Resources: `pybun://cache/info`, `pybun://env/info`. HTTP mode remains TODO; stdio is the GA path.

## JSON output examples

All commands support the `--format=json` option (schema v1). Examples:

```bash
pybun --format=json run -c -- "print('hello')"
```

```json
{
  "version": "1",
  "command": "pybun run",
  "status": "ok",
  "detail": {
    "summary": "executed inline code"
  },
  "events": [],
  "diagnostics": []
}
```

Failure example:
```bash
pybun --format=json run missing.py
```

```json
{
  "version": "1",
  "command": "pybun run",
  "status": "error",
  "diagnostics": [
    {
      "kind": "runtime",
      "message": "missing.py not found",
      "hint": "pass -c for inline code or a valid path"
    }
  ]
}
```

Tests/builds emit structured summaries (pass/fail counts, shard info) while keeping the same envelope:
```bash
pybun --format=json test --fail-fast
pybun --format=json build
```

Enable trace IDs for debugging:
```bash
PYBUN_TRACE=1 pybun --format=json run script.py
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PYBUN_ENV` | Path to venv to use |
| `PYBUN_PYTHON` | Path to Python binary |
| `PYBUN_PROFILE` | Default profile (dev/prod/benchmark) |
| `PYBUN_TRACE` | Set to `1` to enable trace ID |
| `PYBUN_LOG` | Log level (debug/info/warn/error) |

## Release note automation

- Generate GA release notes from tags:  
  `python scripts/release/generate_release_notes.py --repo . --previous-tag v0.1.0 --tag v0.2.0 --notes-output release/RELEASE_NOTES.md --changelog CHANGELOG.md`
- Attach the notes to the release manifest (served by installers/self-update via `release_notes` in JSON):  
  `python scripts/release/generate_manifest.py --assets-dir release --version 0.2.0 --channel stable --base-url https://github.com/pybun/pybun/releases/download/v0.2.0 --output pybun-release.json --release-notes release/RELEASE_NOTES.md`
- CI-friendly JSON summary: `python scripts/release/generate_release_notes.py --repo . --previous-tag v0.1.0 --tag v0.2.0 --format json`

## Upgrade guide

See `docs/UPGRADE.md` for pre-GA → GA migration notes, breaking changes, and the recommended CI checks (doc lint/link + release note automation).

## Development

### Requirements

- Rust stable (`rustup`, `cargo`)

### Basic Commands

```bash
# Format
cargo fmt

# Lint
cargo clippy --all-targets --all-features -- -D warnings

# Test
cargo test

# Development scripts
./scripts/dev fmt
./scripts/dev lint
./scripts/dev test
```

### Testing

```bash
# All tests
cargo test

# Specific tests
cargo test cli_smoke
cargo test json_schema
cargo test mcp
```

## Roadmap

- [x] M0: Repository & CI scaffold
- [x] M1: Fast installer (lockfile, resolver, PEP 723)
- [x] M2: Runtime optimization (module finder, lazy import, hot reload)
- [ ] M3: Test runner (discovery, parallel execution, snapshots)
- [x] M4: JSON/MCP & diagnostics
- [ ] M5: Builder & security
- [ ] M6: Remote cache, workspaces

See `docs/PLAN.md` for details.

## Privacy & Telemetry

PyBun does **not** collect telemetry by default (opt-in model).

```bash
# Check telemetry status
pybun telemetry status

# Enable telemetry
pybun telemetry enable

# Disable telemetry
pybun telemetry disable
```

**Collected data (when enabled):**
- Command usage (anonymized)
- Error diagnostics
- Performance metrics

**Never collected:** API keys, tokens, credentials, passwords, or file contents.

Environment override: `PYBUN_TELEMETRY=0|1`

## License

MIT
