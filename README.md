# PyBun (Python Bundle)

<p align="center">
  <strong>🐍 The Agent-First Python Runtime 🤖</strong>
</p>

<p align="center">
  <em>pip + venv + test runner + MCP server — all in one Rust binary.<br>
  Built for AI agents (JSON-first) and humans alike.</em>
</p>

<p align="center">
  <a href="#video-demo">Video Demo</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#why-pybun">Why PyBun?</a> •
  <a href="#mcp-server">MCP Server</a> •
  <a href="#command-reference">Commands</a> •
  <a href="#roadmap">Roadmap</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-blue" alt="Platform">
  <img src="https://img.shields.io/badge/Language-Rust-orange" alt="Rust">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
</p>

---

## Video Demo

<p align="center">
  <a href="https://www.youtube.com/watch?v=335xndnBOmE">
    <img src="https://img.youtube.com/vi/335xndnBOmE/0.jpg" alt="PyBun Video Demo" width="600">
  </a>
</p>

---

## Quick Start

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/VOID-TECHNOLOGY-INC/PyBun/blob/main/examples/PyBun_Quick_Start.ipynb)

**macOS / Linux:**
```bash
curl -LsSf https://raw.githubusercontent.com/VOID-TECHNOLOGY-INC/PyBun/main/scripts/install.sh | sh
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/VOID-TECHNOLOGY-INC/PyBun/main/scripts/install.ps1 | iex
```

**Or via pip/pipx ([PyPI](https://pypi.org/project/pybun-cli/)):**
```bash
pipx install pybun-cli
# or
pip install pybun-cli
```

**Then run:**
```bash
pybun add requests
pybun run -c -- "import requests; print('Hello, PyBun!')"
```

---

## Why PyBun?

Existing Python tools are built for **humans**. PyBun is designed for **both AI Agents and humans**.

| Feature | Traditional Tools (pip, uv, Poetry) | PyBun |
|---------|-------------------------------------|-------|
| **Output Format** | Human-readable text | 🤖 **JSON-first** (`--format=json`) |
| **AI Integration** | Manual parsing required | 🔌 **Built-in MCP Server** |
| **Error Handling** | Unstructured error messages | 📋 **Structured diagnostics with hints** |
| **Agent Automation** | Fragile text scraping | ✅ **Reliable machine-readable output** |

### ✨ Key Differentiators

- 🤖 **AI Native:** Every command supports `--format=json` as a first-class citizen. LLMs can parse outputs reliably without fragile regex.
- 🔌 **MCP Server Built-in:** [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) lets AI tools like Cursor and Claude Desktop operate your Python environment directly—no extra setup.
- ⚡ **Rust Speed:** Blazingly fast dependency resolution and installation.
- 🛡️ **Sandbox Mode:** Run untrusted AI-generated code safely with `--sandbox`.
- 📦 **Single Binary:** No dependencies. Just download and run.

### 💡 Example: AI Agent Workflow

```bash
# AI agent asks: "Install pandas and show the version"
$ pybun --format=json add pandas
{"status": "ok", "detail": {"added": ["pandas==2.2.0"], ...}}

$ pybun --format=json run -c -- "import pandas; print(pandas.__version__)"
{"status": "ok", "stdout": "2.2.0\n", ...}
```

The AI receives structured JSON—no regex parsing needed.

---

## Status

- **Current:** M1 (Fast Installer), M2 (Runtime Optimization), and M4 (MCP/JSON) are partially stable.
  - `pybun install` / `pybun x` (with uv backend) / `pybun runs` are **Stable**.
  - `pybun watch` (Native) / `pybun test` (Wrapper) are **Preview**.
  - Windows support is **Preview**.
- **Platforms:** macOS/Linux (arm64/amd64), Windows (preview)

> For feature maturity (stub/preview/stable) and phased rollout policy, see [`docs/SPECS.md`](docs/SPECS.md).

---

## Installation

The easiest way to install PyBun:

```bash
pip install pybun-cli
```

<details>
<summary><strong>Other installation methods</strong></summary>

**macOS / Linux (shell script):**
```bash
curl -LsSf https://raw.githubusercontent.com/VOID-TECHNOLOGY-INC/PyBun/main/scripts/install.sh | sh
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/VOID-TECHNOLOGY-INC/PyBun/main/scripts/install.ps1 | iex
```

**From source:**
```bash
cargo install --path .
```

</details>

> **Note:** If your PATH resolves `pybun` to [Bun](https://bun.sh), use `pybun-cli` instead.

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

Install a package in a temporary environment and execute it (Python version of `npx`).
If `uv` is available, it is used for faster environment creation.

```bash
# Temporarily install and run cowsay
# (Use -t flag for Python cowsay package)
pybun x cowsay -- -t "Hello"

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
Tools: `pybun_resolve`, `pybun_install`, `pybun_run`, `pybun_gc`, `pybun_doctor`. Resources: `pybun://cache/info`, `pybun://env/info`.

### Configuration (Claude Desktop)

Add to your `claude_desktop_config.json`:

#### Option 1: Using `uvx` (No install required)
```json
{
  "mcpServers": {
    "pybun": {
      "command": "uvx",
      "args": [
        "--from",
        "pybun-cli",
        "pybun",
        "mcp",
        "serve",
        "--stdio"
      ]
    }
  }
}
```

#### Option 2: Using pip install
Requires `pip install pybun-cli`.
```json
{
  "mcpServers": {
    "pybun": {
      "command": "pybun",
      "args": [
        "mcp",
        "serve",
        "--stdio"
      ]
    }
  }
}
```
*Note: If `pybun` is not in the PATH, provide the absolute path (e.g., `/Users/username/bin/pybun`).*

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
  `python scripts/release/generate_manifest.py --assets-dir release --version 0.2.0 --channel stable --base-url https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v0.2.0 --output pybun-release.json --release-notes release/RELEASE_NOTES.md`
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
