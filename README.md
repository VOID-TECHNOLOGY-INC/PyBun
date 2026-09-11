# PyBun (Python Bundle)

<p align="center">
  <strong>🐍 The Agent-Native Python Control Plane 🤖</strong>
</p>

<p align="center">
  <em>Safe, structured, deterministic Python execution for AI coding agents —<br>
  orchestrating Python, pytest, and command-specific uv backends with JSON-first output and a built-in MCP server.</em>
</p>

<p align="center">
  <a href="#video-demo">Video Demo</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#why-pybun">Why PyBun?</a> •
  <a href="#mcp-server">MCP Server</a> •
  <a href="#command-reference">Commands</a> •
  <a href="#benchmarks">Benchmarks</a> •
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
pybun run -c "import requests; print('Hello, PyBun!')"
```

---

## Why PyBun?

Existing Python tools are built for **humans**. PyBun is designed for **AI agents** — and humans who work alongside them.

**PyBun is not a speed competitor to uv.** Tools like uv and pip are excellent at dependency resolution and installation. PyBun adds an **agent-facing control layer**: structured output, MCP integration, sandboxed execution, and audit/provenance that AI systems can rely on without fragile text scraping or unverifiable side effects. Delegation is currently command-specific: `pybun x` and eligible PEP 723 script runs use uv when it is available, while ordinary dependency commands still use PyBun's native path.

The value PyBun adds isn't "faster pip." It's removing the ambiguity, non-determinism, and risk an agent faces when it operates a Python environment on its own.

### Design Philosophy

```text
           AI Agent
              │  MCP / JSON
              ▼
        ┌───────────────┐
        │     PyBun      │   Policy · Sandbox · Schema
        │ Control Plane  │   Diagnostics · Audit · Provenance
        └───────┬────────┘
                │  delegates execution
      ┌─────────┼─────────┐
      ▼         ▼         ▼
     uv       pytest    Python
```

PyBun is moving toward a thin, structured control layer on top of proven execution backends rather than expanding its reimplementation of the Python packaging/import ecosystem. The v0.2.0 target architecture broadens uv delegation; it does not describe every current command path. See [`docs/SPECS.md`](docs/SPECS.md#03-外部レビューによる方向性提言-2026-08-29) for the reasoning behind this scope decision.

### ✨ What PyBun adds that other tools don't

- 🤖 **JSON-first output:** Every command supports `--format=json` as a first-class citizen. LLMs can parse outputs reliably — no regex, no brittle string matching.
- 🔌 **Built-in MCP Server:** [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) lets AI tools like Cursor and Claude Desktop operate your Python environment directly via stdio — no extra glue code required.
- 📋 **Structured diagnostics:** Errors come with machine-readable `code`, `level`, and `message` fields. Agents can act on failures without guessing what went wrong.
- 🛡️ **Sandbox Mode:** Run untrusted AI-generated code safely with `--sandbox`. File and network access are restricted when the flag is set.
- 📦 **Single binary:** No runtime dependencies. Download and run anywhere.

### 💡 Example: AI Agent Workflow

```bash
# AI agent asks: "Install pandas and show the version"
$ pybun --format=json add pandas
{"status": "ok", "detail": {"added": ["pandas==2.2.0"], ...}}

$ pybun --format=json run -c "import pandas; print(pandas.__version__)"
{"status": "ok", "stdout": "2.2.0\n", ...}
```

The AI receives structured JSON — no parsing required, no ambiguity.

---

## Status

Maturity is assigned per execution path rather than to an entire milestone:

| Surface | Maturity | Current execution path |
| --- | --- | --- |
| `pybun install` | **Preview** | PyBun's native resolver, downloader, and wheel installer. Path containment is hardened by [Issue #431](https://github.com/VOID-TECHNOLOGY-INC/PyBun/issues/431), but this is not a claim of full Python packaging compatibility. |
| `pybun x` | **Stable for common cases** | Creates a temporary environment and uses `uv pip install` when uv is available; otherwise it falls back to pip. |
| `pybun run` | **Stable for common cases** | Runs ordinary scripts with Python. Eligible PEP 723 scripts use `uv run --script` automatically when uv is available. Other PEP 723 paths are orchestrated by PyBun and may still use `uv pip install` for dependencies. |
| `pybun test` | **Stable for common cases** | The default backend wraps pytest/unittest. `--backend=pybun` is **Preview** and reports `W_TEST_BACKEND_COMPAT_*` diagnostics for known plugin/fixture gaps. |
| `pybun watch` | **Preview** | Native monitoring on macOS/Linux, with polling fallback on standard builds. |
| `pybun module-find` | **Experimental** | Standalone Rust Module Finder; it is not wired into CPython's runtime import path ([Issue #403](https://github.com/VOID-TECHNOLOGY-INC/PyBun/issues/403)). |
| Windows support | **Preview** | CI compile coverage and selected cross-platform behavior; continue to validate command-specific behavior. |

`pybun install`, `pybun lock`, and `pybun upgrade` use PyBun's native dependency path today; installing uv does not switch those commands to an uv backend. Broader dependency-operation delegation is a v0.2.0 target.

PyBun-managed PEP 723 environments may still use `uv pip install` for dependency installation when uv is available, including sandboxed, no-cache, and PyBun-lockfile paths. Without uv, those paths fall back to native resolution/installation or pip depending on the environment mode. This is separate from direct `uv run --script` delegation.

The native installer's `.data/{purelib,platlib,scripts,headers,data}` routing is implemented and tested by the work that closed [Issue #402](https://github.com/VOID-TECHNOLOGY-INC/PyBun/issues/402). That tested subset includes relocation, script permissions/shebang handling, and headers placement; it does not promise complete wheel compatibility such as console-entry-point generation, every platform scheme, source distributions, or arbitrary install hooks.

- **Platforms:** macOS/Linux (arm64/amd64), Windows (preview)

> PyBun's priority is the agent-facing control layer (JSON/MCP/diagnostics/sandbox/audit/drift), not re-implementing Python packaging/import internals. See [`docs/SPECS.md`](docs/SPECS.md#03-外部レビューによる方向性提言-2026-08-29) for feature maturity, phased rollout policy, and the current scope decisions.

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
# Initialize a new project (pyproject.toml)
pybun init
pybun init --name my-project --python ">=3.11" --template package

# Install dependencies (generates lockfile)
pybun install --require requests==2.31.0 --index fixtures/index.json

# Add a package (updates pyproject.toml)
pybun add requests

# Remove a package
pybun remove requests

# Lock dependencies for a PEP 723 script
pybun lock --script script.py

# Check for outdated dependencies
pybun outdated

# Upgrade dependencies within constraints (or specific packages)
pybun upgrade
pybun upgrade requests
pybun upgrade --dry-run
```

### Script Execution

```bash
# Run a Python script
pybun run script.py

# Run with arguments
pybun run script.py -- arg1 arg2

# Run inline code
pybun run -c "import sys; print(sys.version)"

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
※ Metadata parsing and isolated-environment execution are supported. Direct `uv run --script` is Stable for common cases; PyBun-managed fallback paths inherit the native installer's Preview limitations. Environments are cached per script/dependency/Python-version key; see `docs/PLAN.md` for details.

### Ad-hoc Execution (`pybun x`)

Install a package in a temporary environment and execute it (Python version of `npx`).
The environment is created with `python -m venv`. If `uv` is available, PyBun uses `uv pip install` for package installation; otherwise it uses pip.

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

> These commands (Module Finder, Lazy Import, Watch) are opportunistic performance optimizations, evaluated independently for ROI — they are not required for PyBun's core agent-control-plane value (JSON/MCP/diagnostics/sandbox). Module Finder in particular is not yet connected to CPython's runtime import resolution (Issue #403).

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
# Native watching (macOS/Linux, `native-watch` feature) or a polling fallback
# (standard builds) is used automatically. --shell-command remains available
# for an external watcher.
pybun watch main.py

# Watch a specific directory
pybun watch main.py -p src

# Show configuration
pybun watch --show-config

# Generate shell command for external watcher
pybun watch --shell-command main.py
```

#### Dependency Drift

Detect undeclared imports and unused declared dependencies:

```bash
pybun drift
pybun drift --path ./src
```

#### Vulnerability Scanning

Scan installed packages against the [OSV](https://osv.dev) database (same scan logic as the MCP `pybun_audit` tool):

```bash
pybun audit

# Only report medium severity and above
pybun audit --severity-threshold=medium

# Exit non-zero when high/critical vulnerabilities are found (CI gating)
pybun audit --fail-on=high
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

Tools: `pybun_resolve`, `pybun_install`, `pybun_run`, `pybun_gc`, `pybun_doctor`, `pybun_lint`, `pybun_type_check`, `pybun_profile`, `pybun_fix`  
Resources: `pybun://cache/info`, `pybun://env/info`, `pybun://audit/recent`

※ Currently **`pybun_gc`, `pybun_doctor`, `pybun_run`, `pybun_resolve`, `pybun_lint`, `pybun_type_check`, `pybun_profile`, `pybun_fix`, and resources are operational**. `pybun_install` generates lockfiles via resolution. HTTP mode is not yet implemented.

`pybun_run` is sandboxed by default for MCP-originated calls. To preview code without executing it, pass `dry_run: true`; to disable the sandbox, pass `unsafe_no_sandbox: true` and treat the warning in the response as an approval checkpoint.

### Build

```bash
# Build sdist/wheel artifacts (wraps `python -m build`)
pybun build

# Build and emit a CycloneDX SBOM alongside artifacts
pybun build --sbom
```

### Diagnostics & Maintenance

```bash
# Environment diagnostics
pybun doctor
pybun doctor --verbose

# Compute a remediation plan for detected issues (preview)
pybun doctor --fix

# Apply safe, auto-applicable fixes from the remediation plan
pybun doctor --fix --apply

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
Tools: `pybun_resolve`, `pybun_install`, `pybun_run`, `pybun_gc`, `pybun_doctor`, `pybun_lint`, `pybun_type_check`, `pybun_profile`, `pybun_fix`. Resources: `pybun://cache/info`, `pybun://env/info`, `pybun://audit/recent`.

MCP `pybun_run` applies the sandbox by default, including process/file-size limits and secret-like environment variable filtering. Use `sandbox_policy` to allow network/path/env exceptions, `dry_run: true` for a non-executing plan, or `unsafe_no_sandbox: true` only in controlled environments.

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
pybun --format=json run -c "print('hello')"
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

Print or validate the JSON schema itself:
```bash
pybun schema print
pybun schema check
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PYBUN_ENV` | Path to venv to use |
| `PYBUN_PYTHON` | Path to Python binary |
| `PYBUN_PROFILE` | Default profile (dev/prod/benchmark) |
| `PYBUN_TRACE` | Set to `1` to enable trace ID |
| `PYBUN_HOME` | Override cache root directory |
| `PYBUN_TELEMETRY` | Override telemetry setting (0/1) |
| `PYBUN_PROGRESS` | Override `--progress` (auto/always/never) |
| `PYBUN_PYPI_BASE_URL` | Override the PyPI index base URL |
| `PYBUN_PYPI_CACHE_DIR` | Override the PyPI metadata cache directory. By default this uses the platform cache directory plus `pybun/pypi` (for example `~/Library/Caches/pybun/pypi` on macOS). Current binary cache entries use `.bin`; legacy `.json` entries are only read from the same directory as a fallback. |
| `PYBUN_AUDIT_LOG` | Override the MCP audit log path (`/dev/null` disables it) |
| `PYBUN_SANDBOX_ALLOW_NETWORK` | Allow network access under `--sandbox` |

See `CLAUDE.md`'s Environment Variables section for the full list, including testing/dry-run-only variables.

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

## Benchmarks

PyBun is not a speed competitor to uv — it is an interface layer. Current uv delegation is limited to command paths such as `pybun x` package installation and eligible PEP 723 script runs. Ordinary `pybun install`, `pybun lock`, and `pybun upgrade` still use native dependency code; the v0.2.0 architecture aims to delegate more of that work.

The areas where PyBun intentionally differs from uv (JSON output, MCP, sandbox) are evaluated for structured correctness and safety first. Native resolver performance work and measurements are tracked in [Issue #239](https://github.com/VOID-TECHNOLOGY-INC/PyBun/issues/239); they should not be read as a product goal to out-run uv.

Full numbers: [docs/BENCHMARK_UV_COMPARISON.md](docs/BENCHMARK_UV_COMPARISON.md)

---

## Roadmap

- [x] M0: Repository & CI scaffold
- [x] M1: Installer foundation (lockfile, native resolver, PEP 723); native install remains Preview while the v0.2.0 backend transition is pending
- [x] M2: Runtime optimization (module finder, lazy import, hot reload) — *opportunistic, ROI under evaluation; see [Issue #403](https://github.com/VOID-TECHNOLOGY-INC/PyBun/issues/403)*
- [x] M3: Test runner (discovery, parallel execution, snapshots)
- [x] M4: JSON/MCP & diagnostics
- [ ] M5: Agent control plane hardening (extended `doctor`/`drift`, audit/provenance depth) — reprioritized over a full native wheel installer; see [`docs/SPECS.md` §0.3](docs/SPECS.md#03-外部レビューによる方向性提言-2026-08-29)
- [ ] M6: Release hardening (remote cache, workspaces, telemetry)

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
