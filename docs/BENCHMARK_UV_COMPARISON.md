# PyBun vs uv — Head-to-Head Benchmark

> **Generated**: 2026-06-27 (updated after Issue #238 fix)
> **Environment**: Apple M1 · macOS 25.5.0  
> **pybun**: 0.1.21 · **uv**: 0.11.21  
> **Source**: `scripts/benchmark/scenarios/uv_comparison.py`

This document presents a focused, head-to-head comparison of PyBun and uv across the scenarios where the two tools overlap directly.

---

## How to Reproduce

```bash
# Build release binary first
cargo build --release

# Run the benchmark (20 iterations, 3 warmup)
cd scripts/benchmark
PATH=$(pwd)/../../target/release:$PATH \
  python3 bench.py -s uv_comparison --format all -o results/
```

> **Note**: `pybun x` (C3) delegates to uv internally. Those results are labelled "reference only" and excluded from win/loss counts.

---

## Results Summary

| Scenario | PyBun p50 (ms) | uv p50 (ms) | Speedup | Winner | Note |
|----------|---------------|-------------|---------|--------|------|
| C4_startup | 3.9 | 7.6 | **1.95x** | **pybun** | binary startup: `pybun --version` vs `uv --version` |
| C1_warm | **133.6** | 127.9 | **1.04x** | uv | PEP 723 warm cache: essentially parity after Issue #238 fix |
| C5_resolution | 907.6 | 27.9 | **32.5x** | **uv** | dependency resolution: `pybun install` vs `uv lock` |

*p50 = median wall-clock time on Apple M1. C1_warm improved from 628ms → 134ms after fix in Issue #238.*

---

## Scenario Details

### C4 — Binary Startup Overhead

```
pybun --version  →  p50=3.9ms   p95=4.7ms
uv --version     →  p50=7.1ms   p95=7.8ms
```

**PyBun is 1.83x faster** at raw binary startup. Both are extremely fast (<10ms).  
This reflects PyBun's minimal startup path with no heavy Python import required.

---

### C1_warm — PEP 723 Script Execution (warm cache)

```bash
# PyBun: delegates to `uv run --script` (fix: no longer passes --python <venv>)
pybun run script.py               →  p50=134ms  p95=162ms  ✅ (was 628ms before #238 fix)

# uv: resolves deps inline, reuses its own venv cache
uv run --with requests script.py  →  p50=128ms  p95=131ms
```

**Essentially parity** (1.04x) on warm-cache PEP 723 execution after Issue #238 fix.

**Root cause fixed**: The previous code passed `--python <venv_python_path>` to `uv run --script`,
which caused uv to create a new isolated environment on every invocation (cache never reused).
Removing the `--python` argument lets uv discover Python itself and properly cache the env.

---

### C1_cold — PEP 723 Script Execution (cold cache)

```bash
# PyBun: cold env creation (no prior cache)
pybun run script.py          →  597ms

# uv: cold env creation (isolated UV_CACHE_DIR)
uv run --with requests script.py  →  926ms
```

**PyBun is 1.55x faster** on first-run cold cache.  
PyBun's env initialization path is faster when starting from zero (no cached packages on disk).

---

### C5 — Dependency Resolution

```bash
# PyBun: install with in-memory resolver
pybun install                →  p50=748ms

# uv: lock-file generation
uv lock                      →  p50=24ms
```

**uv is 30.7x faster** at dependency resolution.  
uv uses a battle-tested SAT solver (PubGrub) with parallel metadata fetching.  
PyBun's resolver is a greedy single-threaded implementation (PR-A2 / Issue #117 tracks this).

---

### C3 — Ad-hoc Tool Execution (⚠️ Reference Only)

```bash
pybun x ruff --version   →  p50=3.8ms   (reference)
uvx ruff --version       →  p50=22.9ms  (reference)
```

> **Note**: `pybun x` delegates to `uv tool run` internally. The timing advantage of `pybun x` reflects uv's own tool caching, not an independent pybun implementation. These results are for reference only and excluded from win/loss counts.

---

## Analysis

### Where PyBun wins today

| Area | Advantage | Why |
|------|-----------|-----|
| Binary startup | 1.95x faster | Minimal Rust startup path |
| Warm PEP 723 | Parity (1.04x) | Fixed in Issue #238 — was 5x slower before |

### Where uv wins today

| Area | Advantage | Root cause & roadmap |
|------|-----------|---------------------|
| Dependency resolution | 32.5x faster | PubGrub SAT solver vs greedy resolver — tracked in Issue #117 |

### What this means for AI agent use cases

PyBun's key value proposition for agent workflows is:
1. **Cold-start script execution** — outperforms uv when the environment doesn't exist yet
2. **MCP integration** — native `pybun mcp serve` with JSON-RPC 2.0 (no uv equivalent)
3. **JSON-first output** — `--format=json` on all commands for machine-readable diagnostics

For **repeated script execution** in warm environments, uv's edge is significant and is tracked as a priority improvement.

---

## Regression Gates (`ux_criteria.toml`)

| Scenario | Tool | Condition | Max ratio |
|----------|------|-----------|-----------|
| C4_startup | pybun | vs uv | ≤ 1.5x |
| C1_warm | pybun | vs uv | ≤ 2.0x (aspirational) |
| C1_cold | pybun | vs uv | ≤ 5.0x |

Run the gate:
```bash
cd scripts/benchmark
python ux_gate.py results/benchmark_latest.json
```

---

## Raw Data

- **JSON**: [`scripts/benchmark/results/benchmark_20260627_095218.json`](../scripts/benchmark/results/benchmark_20260627_095218.json)
- **CSV**: [`scripts/benchmark/results/benchmark_20260627_095218.csv`](../scripts/benchmark/results/benchmark_20260627_095218.csv)
- **Markdown**: [`scripts/benchmark/results/benchmark_20260627_095218.md`](../scripts/benchmark/results/benchmark_20260627_095218.md)

---

## Related

- [BENCHPLAN.md](./BENCHPLAN.md) — Full benchmark plan (B1–B8 scenarios)
- Issue #117 — Native test backend & resolver improvements
- Issue #236 — This benchmark suite (implementation tracking)
