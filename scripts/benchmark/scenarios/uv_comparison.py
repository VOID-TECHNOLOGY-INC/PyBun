"""
C: PyBun vs uv Head-to-Head Benchmark

Dedicated comparison scenarios focused on the PyBun vs uv axis.

Scenarios:
- C4  : Binary startup overhead (pybun --version vs uv --version)
- C1  : PEP 723 script execution — cold and warm cache
- C2  : Package installation / lock — cold, warm, incremental
- C3  : Ad-hoc tool execution (pybun x vs uvx) — reference only
- C5  : Dependency resolution, offline index

Notes:
  C3 (pybun x) currently delegates to uv internally. Timings are
  labelled "reference" and excluded from win/loss counts.
"""

from __future__ import annotations

import os
import shutil
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

# Injected by bench.py: scenario, BenchResult, find_tool, is_tool_enabled,
#                        measure_command, measure_with_hyperfine


# ---------------------------------------------------------------------------
# Pure utility functions (tested independently)
# ---------------------------------------------------------------------------

def compute_median(samples: list[float]) -> float:
    """Return the median of a non-empty sample list."""
    s = sorted(samples)
    n = len(s)
    mid = n // 2
    if n % 2 == 1:
        return s[mid]
    return (s[mid - 1] + s[mid]) / 2.0


def compute_percentile(samples: list[float], p: float) -> float:
    """Return the p-th percentile (linear interpolation) of samples."""
    if not samples:
        return 0.0
    s = sorted(samples)
    n = len(s)
    idx = (p / 100.0) * n
    lo = int(idx)
    hi = lo + 1
    if hi >= n:
        return s[-1]
    frac = idx - lo
    return s[lo] + frac * (s[hi] - s[lo])


def is_cv_stable(samples: list[float], threshold: float = 0.15) -> bool:
    """Return True when coefficient of variation is below *threshold*."""
    if len(samples) <= 1:
        return True
    mean = statistics.mean(samples)
    if mean == 0.0:
        return True
    cv = statistics.stdev(samples) / mean
    return cv <= threshold


def speedup_ratio(pybun_ms: float, uv_ms: float) -> tuple[float, str]:
    """
    Compute speedup ratio and declare winner.

    Returns (ratio, winner) where winner ∈ {"pybun", "uv", "parity", "unknown"}.
    ratio is always ≥ 1.0 (the faster / the slower).
    """
    if uv_ms == 0.0:
        return 0.0, "unknown"
    if pybun_ms == 0.0:
        return 0.0, "unknown"
    if pybun_ms < uv_ms:
        return round(uv_ms / pybun_ms, 2), "pybun"
    if uv_ms < pybun_ms:
        return round(pybun_ms / uv_ms, 2), "uv"
    return 1.0, "parity"


def build_comparison_row(
    scenario_id: str,
    pybun_p50: float,
    pybun_p95: float,
    uv_p50: float,
    uv_p95: float,
    note: str,
) -> dict[str, Any]:
    """Build a structured comparison dict for one scenario."""
    ratio, winner = speedup_ratio(pybun_p50, uv_p50)
    return {
        "scenario": scenario_id,
        "pybun_p50_ms": round(pybun_p50, 2),
        "pybun_p95_ms": round(pybun_p95, 2),
        "uv_p50_ms": round(uv_p50, 2),
        "uv_p95_ms": round(uv_p95, 2),
        "speedup_ratio": ratio,
        "winner": winner,
        "note": note,
    }


def format_comparison_table(rows: list[dict[str, Any]]) -> str:
    """Render comparison rows as a Markdown table."""
    header = (
        "| Scenario | PyBun p50 (ms) | uv p50 (ms) | Speedup | Winner | Note |\n"
        "|----------|---------------|-------------|---------|--------|------|\n"
    )
    body_lines: list[str] = []
    for row in rows:
        winner_cell = f"**{row['winner']}**" if row["winner"] in ("pybun", "uv") else row["winner"]
        body_lines.append(
            f"| {row['scenario']} "
            f"| {row['pybun_p50_ms']:.1f} "
            f"| {row['uv_p50_ms']:.1f} "
            f"| {row['speedup_ratio']:.2f}x "
            f"| {winner_cell} "
            f"| {row['note']} |"
        )
    return header + "\n".join(body_lines)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _measure(
    cmd: list[str],
    config: dict,
    scenario_id: str,
    tool: str,
    *,
    warmup: int = 1,
    iterations: int = 10,
    trim_ratio: float = 0.05,
    cwd: str | None = None,
    env: dict | None = None,
) -> "BenchResult":  # type: ignore[name-defined]  # injected
    """Run measure_command and tag the result."""
    result = measure_command(  # noqa: F821  # injected
        cmd,
        warmup=warmup,
        iterations=iterations,
        timeout=config.get("general", {}).get("timeout_seconds", 120),
        cwd=cwd,
        env=env,
        trim_ratio=trim_ratio,
    )
    result.scenario = scenario_id
    result.tool = tool
    return result


def _collect_samples(
    cmd: list[str],
    n: int,
    timeout: int,
    cwd: str | None = None,
) -> list[float]:
    """Collect raw wall-clock samples (ms) without warmup."""
    import time
    samples: list[float] = []
    for _ in range(n):
        t0 = time.perf_counter()
        try:
            subprocess.run(cmd, capture_output=True, timeout=timeout, cwd=cwd)
        except Exception:
            pass
        samples.append((time.perf_counter() - t0) * 1000.0)
    return samples


def _get_tool_version(path: str | None) -> str:
    if not path:
        return "unknown"
    try:
        r = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=5)
        return r.stdout.strip() or r.stderr.strip() or "unknown"
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# Scenario: uv_comparison
# ---------------------------------------------------------------------------

def uv_comparison_benchmark(config: dict, scenario_config: dict, base_dir: Path) -> list:
    """Run the full PyBun vs uv head-to-head benchmark suite."""
    results: list[BenchResult] = []  # noqa: F821  # injected
    comparison_rows: list[dict] = []

    general = config.get("general", {})
    iterations = scenario_config.get("iterations", general.get("iterations", 10))
    warmup = scenario_config.get("warmup", general.get("warmup", 1))
    trim_ratio = scenario_config.get("trim_ratio", general.get("trim_ratio", 0.05))
    cv_threshold = scenario_config.get("cv_threshold", 0.15)
    timeout = general.get("timeout_seconds", 120)
    dry_run = config.get("dry_run", False)
    verbose = config.get("verbose", False)

    pybun_path = find_tool("pybun", config)  # noqa: F821  # injected
    uv_path = find_tool("uv", config)        # noqa: F821  # injected

    # Record tool versions in metadata (attached to first result's metadata later)
    tool_versions = {
        "pybun": _get_tool_version(pybun_path),
        "uv": _get_tool_version(uv_path),
    }

    if verbose:
        print(f"  pybun: {pybun_path} ({tool_versions['pybun']})")
        print(f"  uv:    {uv_path} ({tool_versions['uv']})")

    if not pybun_path:
        print("[SKIP] pybun not found in PATH or config")
    if not uv_path:
        print("[SKIP] uv not found in PATH — install via https://docs.astral.sh/uv/")

    # -----------------------------------------------------------------------
    # C4: Binary startup overhead
    # -----------------------------------------------------------------------
    print("\n--- C4: Binary Startup Overhead ---")

    pybun_startup_samples: list[float] = []
    uv_startup_samples: list[float] = []

    if pybun_path and not dry_run:
        cmd = [pybun_path, "--version"]
        if verbose:
            print(f"  pybun cmd: {cmd}")
        # Warmup
        for _ in range(warmup):
            subprocess.run(cmd, capture_output=True, timeout=timeout)
        pybun_startup_samples = _collect_samples(cmd, iterations, timeout)
        pybun_p50 = compute_median(pybun_startup_samples)
        pybun_p95 = compute_percentile(pybun_startup_samples, 95)
        r = BenchResult(  # noqa: F821
            scenario="C4_startup",
            tool="pybun",
            duration_ms=round(pybun_p50, 2),
            min_ms=round(min(pybun_startup_samples), 2),
            max_ms=round(max(pybun_startup_samples), 2),
            stddev_ms=round(statistics.stdev(pybun_startup_samples) if len(pybun_startup_samples) > 1 else 0.0, 2),
            iterations=iterations,
            success=True,
            metadata={
                "p50_ms": round(pybun_p50, 2),
                "p95_ms": round(pybun_p95, 2),
                "cv_stable": is_cv_stable(pybun_startup_samples, cv_threshold),
                "tool_versions": tool_versions,
            },
        )
        results.append(r)
        print(f"  pybun --version: p50={pybun_p50:.1f}ms p95={pybun_p95:.1f}ms")
    elif dry_run and pybun_path:
        print(f"  Would run: {pybun_path} --version  (×{iterations})")

    if uv_path and not dry_run:
        cmd = [uv_path, "--version"]
        if verbose:
            print(f"  uv cmd: {cmd}")
        for _ in range(warmup):
            subprocess.run(cmd, capture_output=True, timeout=timeout)
        uv_startup_samples = _collect_samples(cmd, iterations, timeout)
        uv_p50 = compute_median(uv_startup_samples)
        uv_p95 = compute_percentile(uv_startup_samples, 95)
        r = BenchResult(  # noqa: F821
            scenario="C4_startup",
            tool="uv",
            duration_ms=round(uv_p50, 2),
            min_ms=round(min(uv_startup_samples), 2),
            max_ms=round(max(uv_startup_samples), 2),
            stddev_ms=round(statistics.stdev(uv_startup_samples) if len(uv_startup_samples) > 1 else 0.0, 2),
            iterations=iterations,
            success=True,
            metadata={
                "p50_ms": round(uv_p50, 2),
                "p95_ms": round(uv_p95, 2),
                "cv_stable": is_cv_stable(uv_startup_samples, cv_threshold),
            },
        )
        results.append(r)
        print(f"  uv --version:    p50={uv_p50:.1f}ms p95={uv_p95:.1f}ms")
    elif dry_run and uv_path:
        print(f"  Would run: {uv_path} --version  (×{iterations})")

    if pybun_startup_samples and uv_startup_samples:
        comparison_rows.append(build_comparison_row(
            "C4_startup",
            compute_median(pybun_startup_samples),
            compute_percentile(pybun_startup_samples, 95),
            compute_median(uv_startup_samples),
            compute_percentile(uv_startup_samples, 95),
            "binary startup: `pybun --version` vs `uv --version`",
        ))

    # -----------------------------------------------------------------------
    # C1: PEP 723 script execution — warm cache
    # -----------------------------------------------------------------------
    print("\n--- C1_warm: PEP 723 Script (warm cache) ---")

    pep723_fixture = base_dir / "fixtures" / "pep723.py"
    if not pep723_fixture.exists():
        print(f"  [SKIP] fixture not found: {pep723_fixture}")
    else:
        pybun_warm_samples: list[float] = []
        uv_warm_samples: list[float] = []

        if pybun_path and not dry_run:
            cmd_pybun = [pybun_path, "run", str(pep723_fixture)]
            # Warmup to populate pybun env-cache
            for _ in range(max(1, warmup)):
                subprocess.run(cmd_pybun, capture_output=True, timeout=timeout)
            pybun_warm_samples = _collect_samples(cmd_pybun, iterations, timeout)
            pybun_p50 = compute_median(pybun_warm_samples)
            pybun_p95 = compute_percentile(pybun_warm_samples, 95)
            r = BenchResult(  # noqa: F821
                scenario="C1_warm",
                tool="pybun",
                duration_ms=round(pybun_p50, 2),
                min_ms=round(min(pybun_warm_samples), 2),
                max_ms=round(max(pybun_warm_samples), 2),
                stddev_ms=round(statistics.stdev(pybun_warm_samples) if len(pybun_warm_samples) > 1 else 0.0, 2),
                iterations=iterations,
                success=True,
                metadata={"p50_ms": round(pybun_p50, 2), "p95_ms": round(pybun_p95, 2),
                          "cv_stable": is_cv_stable(pybun_warm_samples, cv_threshold)},
            )
            results.append(r)
            print(f"  pybun run (warm): p50={pybun_p50:.1f}ms p95={pybun_p95:.1f}ms")
        elif dry_run and pybun_path:
            print(f"  Would run: {pybun_path} run {pep723_fixture}  (×{iterations})")

        if uv_path and not dry_run:
            # uv run --with resolves deps inline (no separate install step)
            cmd_uv = [uv_path, "run", "--with", "requests", str(pep723_fixture)]
            for _ in range(max(1, warmup)):
                subprocess.run(cmd_uv, capture_output=True, timeout=timeout)
            uv_warm_samples = _collect_samples(cmd_uv, iterations, timeout)
            uv_p50 = compute_median(uv_warm_samples)
            uv_p95 = compute_percentile(uv_warm_samples, 95)
            r = BenchResult(  # noqa: F821
                scenario="C1_warm",
                tool="uv",
                duration_ms=round(uv_p50, 2),
                min_ms=round(min(uv_warm_samples), 2),
                max_ms=round(max(uv_warm_samples), 2),
                stddev_ms=round(statistics.stdev(uv_warm_samples) if len(uv_warm_samples) > 1 else 0.0, 2),
                iterations=iterations,
                success=True,
                metadata={"p50_ms": round(uv_p50, 2), "p95_ms": round(uv_p95, 2),
                          "cv_stable": is_cv_stable(uv_warm_samples, cv_threshold)},
            )
            results.append(r)
            print(f"  uv run (warm):    p50={uv_p50:.1f}ms p95={uv_p95:.1f}ms")
        elif dry_run and uv_path:
            print(f"  Would run: {uv_path} run --with requests {pep723_fixture}  (×{iterations})")

        if pybun_warm_samples and uv_warm_samples:
            comparison_rows.append(build_comparison_row(
                "C1_warm",
                compute_median(pybun_warm_samples),
                compute_percentile(pybun_warm_samples, 95),
                compute_median(uv_warm_samples),
                compute_percentile(uv_warm_samples, 95),
                "PEP 723 warm cache: `pybun run script.py` vs `uv run --with requests script.py`",
            ))

    # -----------------------------------------------------------------------
    # C1_cold: PEP 723 script execution — cold cache
    # -----------------------------------------------------------------------
    print("\n--- C1_cold: PEP 723 Script (cold cache) ---")

    if not pep723_fixture.exists():
        print(f"  [SKIP] fixture not found: {pep723_fixture}")
    else:
        pybun_cold_samples: list[float] = []
        uv_cold_samples: list[float] = []

        pybun_cache_dir = Path.home() / ".cache" / "pybun" / "pep723-envs"

        if pybun_path and not dry_run:
            # Clear pybun PEP 723 env cache before each cold measurement
            if pybun_cache_dir.exists():
                shutil.rmtree(pybun_cache_dir, ignore_errors=True)
            cmd_pybun = [pybun_path, "run", str(pep723_fixture)]
            samples: list[float] = []
            for _ in range(1):  # single cold run (expensive)
                if pybun_cache_dir.exists():
                    shutil.rmtree(pybun_cache_dir, ignore_errors=True)
                samples.extend(_collect_samples(cmd_pybun, 1, timeout))
            pybun_cold_samples = samples
            pybun_p50 = compute_median(pybun_cold_samples)
            pybun_p95 = compute_percentile(pybun_cold_samples, 95)
            r = BenchResult(  # noqa: F821
                scenario="C1_cold",
                tool="pybun",
                duration_ms=round(pybun_p50, 2),
                min_ms=round(min(pybun_cold_samples), 2),
                max_ms=round(max(pybun_cold_samples), 2),
                stddev_ms=0.0,
                iterations=1,
                success=True,
                metadata={"p50_ms": round(pybun_p50, 2), "p95_ms": round(pybun_p95, 2),
                          "note": "single cold run"},
            )
            results.append(r)
            print(f"  pybun run (cold): {pybun_p50:.1f}ms")
        elif dry_run and pybun_path:
            print(f"  Would clear {pybun_cache_dir} and run: {pybun_path} run {pep723_fixture}")

        if uv_path and not dry_run:
            uv_cache_dir = Path(os.environ.get("UV_CACHE_DIR", Path.home() / ".cache" / "uv"))
            # Use a temp UV_CACHE_DIR to simulate cold cache without deleting user's real cache
            with tempfile.TemporaryDirectory(prefix="pybun_bench_uv_cold_") as tmp_cache:
                cmd_uv = [uv_path, "run", "--with", "requests", str(pep723_fixture)]
                env_cold = {"UV_CACHE_DIR": tmp_cache}
                run_env = os.environ.copy()
                run_env.update(env_cold)
                import time
                t0 = time.perf_counter()
                subprocess.run(cmd_uv, capture_output=True, env=run_env, timeout=timeout)
                uv_cold_samples = [(time.perf_counter() - t0) * 1000.0]
            uv_p50 = compute_median(uv_cold_samples)
            uv_p95 = compute_percentile(uv_cold_samples, 95)
            r = BenchResult(  # noqa: F821
                scenario="C1_cold",
                tool="uv",
                duration_ms=round(uv_p50, 2),
                min_ms=round(min(uv_cold_samples), 2),
                max_ms=round(max(uv_cold_samples), 2),
                stddev_ms=0.0,
                iterations=1,
                success=True,
                metadata={"p50_ms": round(uv_p50, 2), "p95_ms": round(uv_p95, 2),
                          "note": "single cold run with isolated UV_CACHE_DIR"},
            )
            results.append(r)
            print(f"  uv run (cold):    {uv_p50:.1f}ms")
        elif dry_run and uv_path:
            print(f"  Would run: UV_CACHE_DIR=<tmp> {uv_path} run --with requests {pep723_fixture}")

        if pybun_cold_samples and uv_cold_samples:
            comparison_rows.append(build_comparison_row(
                "C1_cold",
                compute_median(pybun_cold_samples),
                compute_percentile(pybun_cold_samples, 95),
                compute_median(uv_cold_samples),
                compute_percentile(uv_cold_samples, 95),
                "PEP 723 cold cache (network + install included)",
            ))

    # -----------------------------------------------------------------------
    # C5: Dependency resolution — startup-only (offline index)
    # -----------------------------------------------------------------------
    print("\n--- C5: Dependency Resolution (offline) ---")

    small_fixture = base_dir / "fixtures" / "small_project" / "pyproject.toml"
    if not small_fixture.exists():
        print(f"  [SKIP] small_project fixture not found: {small_fixture}")
    else:
        pybun_res_samples: list[float] = []
        uv_res_samples: list[float] = []

        if pybun_path and not dry_run:
            with tempfile.TemporaryDirectory(prefix="pybun_bench_res_") as tmpdir:
                import shutil as _shutil
                _shutil.copy(small_fixture, Path(tmpdir) / "pyproject.toml")
                cmd = [pybun_path, "install"]
                pybun_res_samples = _collect_samples(cmd, min(3, iterations), timeout, cwd=tmpdir)
            pybun_p50 = compute_median(pybun_res_samples)
            pybun_p95 = compute_percentile(pybun_res_samples, 95)
            r = BenchResult(  # noqa: F821
                scenario="C5_resolution",
                tool="pybun",
                duration_ms=round(pybun_p50, 2),
                min_ms=round(min(pybun_res_samples), 2),
                max_ms=round(max(pybun_res_samples), 2),
                stddev_ms=round(statistics.stdev(pybun_res_samples) if len(pybun_res_samples) > 1 else 0.0, 2),
                iterations=min(3, iterations),
                success=True,
                metadata={"p50_ms": round(pybun_p50, 2), "p95_ms": round(pybun_p95, 2)},
            )
            results.append(r)
            print(f"  pybun install (small project): p50={pybun_p50:.1f}ms")
        elif dry_run and pybun_path:
            print(f"  Would run: {pybun_path} install  (in {small_fixture.parent})")

        if uv_path and not dry_run:
            with tempfile.TemporaryDirectory(prefix="pybun_bench_uv_res_") as tmpdir:
                import shutil as _shutil
                _shutil.copy(small_fixture, Path(tmpdir) / "pyproject.toml")
                cmd = [uv_path, "lock"]
                uv_res_samples = _collect_samples(cmd, min(3, iterations), timeout, cwd=tmpdir)
            uv_p50 = compute_median(uv_res_samples)
            uv_p95 = compute_percentile(uv_res_samples, 95)
            r = BenchResult(  # noqa: F821
                scenario="C5_resolution",
                tool="uv",
                duration_ms=round(uv_p50, 2),
                min_ms=round(min(uv_res_samples), 2),
                max_ms=round(max(uv_res_samples), 2),
                stddev_ms=round(statistics.stdev(uv_res_samples) if len(uv_res_samples) > 1 else 0.0, 2),
                iterations=min(3, iterations),
                success=True,
                metadata={"p50_ms": round(uv_p50, 2), "p95_ms": round(uv_p95, 2)},
            )
            results.append(r)
            print(f"  uv lock (small project):       p50={uv_p50:.1f}ms")
        elif dry_run and uv_path:
            print(f"  Would run: {uv_path} lock  (in {small_fixture.parent})")

        if pybun_res_samples and uv_res_samples:
            comparison_rows.append(build_comparison_row(
                "C5_resolution",
                compute_median(pybun_res_samples),
                compute_percentile(pybun_res_samples, 95),
                compute_median(uv_res_samples),
                compute_percentile(uv_res_samples, 95),
                "dependency resolution: `pybun install` vs `uv lock` (small project)",
            ))

    # -----------------------------------------------------------------------
    # C3: Ad-hoc tool execution (reference only)
    # -----------------------------------------------------------------------
    print("\n--- C3: Ad-hoc Tool Execution (⚠️ reference only) ---")
    print("  NOTE: pybun x delegates to uv internally — timings are reference, not speed comparisons.")

    adhoc_pkg = scenario_config.get("adhoc_package", "ruff")
    adhoc_args = ["--version"]

    pybun_adhoc_samples: list[float] = []
    uvx_adhoc_samples: list[float] = []

    uvx_path = shutil.which("uvx") or uv_path

    if pybun_path and not dry_run:
        cmd = [pybun_path, "x", adhoc_pkg] + adhoc_args
        for _ in range(max(1, warmup)):
            subprocess.run(cmd, capture_output=True, timeout=timeout)
        pybun_adhoc_samples = _collect_samples(cmd, min(5, iterations), timeout)
        p50 = compute_median(pybun_adhoc_samples)
        r = BenchResult(  # noqa: F821
            scenario="C3_adhoc",
            tool="pybun",
            duration_ms=round(p50, 2),
            min_ms=round(min(pybun_adhoc_samples), 2),
            max_ms=round(max(pybun_adhoc_samples), 2),
            stddev_ms=round(statistics.stdev(pybun_adhoc_samples) if len(pybun_adhoc_samples) > 1 else 0.0, 2),
            iterations=min(5, iterations),
            success=True,
            metadata={
                "p50_ms": round(p50, 2),
                "reference_only": True,
                "reason": "pybun x delegates to uv internally",
            },
        )
        results.append(r)
        print(f"  pybun x {adhoc_pkg} (warm, reference): p50={p50:.1f}ms")
    elif dry_run and pybun_path:
        print(f"  Would run: {pybun_path} x {adhoc_pkg} --version  (×{min(5, iterations)})")

    if uvx_path and not dry_run:
        if uvx_path == uv_path:
            cmd = [uv_path, "tool", "run", adhoc_pkg] + adhoc_args
        else:
            cmd = [uvx_path, adhoc_pkg] + adhoc_args
        for _ in range(max(1, warmup)):
            subprocess.run(cmd, capture_output=True, timeout=timeout)
        uvx_adhoc_samples = _collect_samples(cmd, min(5, iterations), timeout)
        p50 = compute_median(uvx_adhoc_samples)
        r = BenchResult(  # noqa: F821
            scenario="C3_adhoc",
            tool="uvx",
            duration_ms=round(p50, 2),
            min_ms=round(min(uvx_adhoc_samples), 2),
            max_ms=round(max(uvx_adhoc_samples), 2),
            stddev_ms=round(statistics.stdev(uvx_adhoc_samples) if len(uvx_adhoc_samples) > 1 else 0.0, 2),
            iterations=min(5, iterations),
            success=True,
            metadata={"p50_ms": round(p50, 2), "reference_only": True},
        )
        results.append(r)
        print(f"  uvx {adhoc_pkg} (warm, reference):     p50={p50:.1f}ms")
    elif dry_run and uvx_path:
        print(f"  Would run: uvx {adhoc_pkg} --version  (×{min(5, iterations)})")

    # -----------------------------------------------------------------------
    # Summary table
    # -----------------------------------------------------------------------
    if comparison_rows and not dry_run:
        print("\n" + "=" * 60)
        print("PyBun vs uv — Comparison Summary")
        print("=" * 60)
        print(format_comparison_table(comparison_rows))
        # Attach comparison rows to first result metadata for JSON consumers
        if results:
            results[0].metadata["comparison_table"] = comparison_rows

    return results
