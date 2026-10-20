"""
C: PyBun vs uv Head-to-Head Benchmark

Dedicated comparison scenarios focused on the PyBun vs uv axis.

Scenarios:
- C4  : Binary startup overhead (pybun --version vs uv --version)
- C1  : PEP 723 script execution — cold and warm cache
- C2  : Package installation / lock — cold, warm, incremental
- C3  : Ad-hoc tool execution (pybun x vs uvx) — reference only
- C5  : Small-project preparation (pybun install vs uv lock)

Notes:
  C3 (pybun x) currently delegates to uv internally. Timings are
  labelled "reference" and excluded from win/loss counts.
"""

from __future__ import annotations

import shutil
import statistics
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from bench import BenchResult, find_tool, measure_command

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
    warmup: int = 0,
    iterations: int = 1,
    cwd: str | None = None,
    env: dict | None = None,
    cv_threshold: float = 0.15,
) -> BenchResult:  # noqa: F821  # injected
    """Use the shared success/diagnostic contract while preserving C-series medians."""
    result = measure_command(  # noqa: F821  # injected
        cmd,
        warmup=warmup,
        iterations=iterations,
        timeout=config.get("general", {}).get("timeout_seconds", 120),
        cwd=cwd,
        env=env,
        record_samples=True,
    )
    result.scenario = scenario_id
    result.tool = tool
    samples = result.metadata.pop("samples_ms")
    if samples:
        result.duration_ms = round(compute_median(samples), 2)
        result.metadata.update(
            p50_ms=result.duration_ms,
            p95_ms=round(compute_percentile(samples, 95), 2),
            cv_stable=is_cv_stable(samples, cv_threshold),
        )
    return result


def _get_tool_version(path: str | None) -> str:
    if not path:
        return "unknown"
    try:
        r = subprocess.run(
            [path, "--version"], capture_output=True, text=True, timeout=5, check=False
        )
        return (
            (r.stdout.strip() or r.stderr.strip()) if r.returncode == 0 else "unknown"
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"


def uv_comparison_benchmark(
    config: dict, scenario_config: dict, base_dir: Path
) -> list:
    """Measure real subprocess outcomes, then compare only successful pairs."""
    general = config.get("general", {})
    iterations = scenario_config.get("iterations", general.get("iterations", 10))
    warmup = scenario_config.get("warmup", general.get("warmup", 1))
    cv_threshold = scenario_config.get("cv_threshold", 0.15)
    dry_run = config.get("dry_run", False)
    pybun_path = find_tool("pybun", config)  # noqa: F821
    uv_path = find_tool("uv", config)  # noqa: F821
    tool_versions = {
        "pybun": _get_tool_version(pybun_path),
        "uv": _get_tool_version(uv_path),
    }
    results: list[BenchResult] = []  # noqa: F821

    def record(
        scenario_id: str,
        tool: str,
        cmd: list[str],
        *,
        count: int = iterations,
        prepare: int = warmup,
        cwd: str | None = None,
        env: dict | None = None,
        note: str | None = None,
    ) -> None:
        if dry_run:
            print(f"  Would run: {cmd} (×{count})")
            return
        result = _measure(
            cmd,
            config,
            scenario_id,
            tool,
            iterations=count,
            warmup=prepare,
            cwd=cwd,
            env=env,
            cv_threshold=cv_threshold,
        )
        if note:
            result.metadata["note"] = note
        if scenario_id == "C3_adhoc":
            result.metadata.update(
                reference_only=True, reason="pybun x delegates to uv internally"
            )
        results.append(result)
        status = "ok" if result.success else f"FAILED: {result.error}"
        print(f"  {scenario_id} {tool}: p50={result.duration_ms:.1f}ms ({status})")

    print("\n--- C4: Binary Startup Overhead ---")
    for tool, path in (("pybun", pybun_path), ("uv", uv_path)):
        if path:
            record("C4_startup", tool, [path, "--version"])
        else:
            print(f"  [SKIP] {tool} not found")

    # Never remove real user caches or generate lockfiles beside repository fixtures.
    with tempfile.TemporaryDirectory(prefix="pybun_bench_compare_") as tmp:
        root = Path(tmp)
        fixture = base_dir / "fixtures" / "pep723.py"
        script = root / "pep723.py"
        if fixture.exists():
            shutil.copyfile(fixture, script)
            print("\n--- C1: PEP 723 Script (warm / cold cache) ---")
            for tool, path in (("pybun", pybun_path), ("uv", uv_path)):
                if not path:
                    continue
                cmd = (
                    [path, "run"]
                    + (["--with", "requests"] if tool == "uv" else [])
                    + [str(script)]
                )
                for cache_state in ("warm", "cold"):
                    cache = root / tool / cache_state
                    env = {
                        "UV_CACHE_DIR": str(cache / "uv"),
                        "PYBUN_HOME": str(cache / "pybun"),
                    }
                    # Separate script paths keep warm-run lockfiles out of cold setup.
                    case_dir = cache / "script"
                    case_dir.mkdir(parents=True)
                    case_script = case_dir / "pep723.py"
                    shutil.copyfile(script, case_script)
                    case_cmd = cmd[:-1] + [str(case_script)]
                    record(
                        f"C1_{cache_state}",
                        tool,
                        case_cmd,
                        count=iterations if cache_state == "warm" else 1,
                        prepare=max(1, warmup) if cache_state == "warm" else 0,
                        cwd=str(case_dir),
                        env=env,
                        note=f"{cache_state} cache with isolated UV_CACHE_DIR and PYBUN_HOME",
                    )
        else:
            print(f"  [SKIP] fixture not found: {fixture}")

        print("\n--- C5: Small-project dependency preparation ---")
        project = base_dir / "fixtures" / "small_project" / "pyproject.toml"
        if project.exists():
            for tool, path, operation in (
                ("pybun", pybun_path, "install"),
                ("uv", uv_path, "lock"),
            ):
                if not path:
                    continue
                cwd = root / tool / "resolution"
                cwd.mkdir(parents=True)
                shutil.copyfile(project, cwd / "pyproject.toml")
                record(
                    "C5_resolution",
                    tool,
                    [path, operation],
                    count=min(3, iterations),
                    prepare=0,
                    cwd=str(cwd),
                    env={
                        "UV_CACHE_DIR": str(cwd / "uv-cache"),
                        "PYBUN_HOME": str(cwd / "pybun-home"),
                    },
                    note="pybun install vs uv lock; includes preparation, not equivalent offline resolution",
                )
        else:
            print(f"  [SKIP] small_project fixture not found: {project}")

        print("\n--- C3: Ad-hoc Tool Execution (reference only) ---")
        package = scenario_config.get("adhoc_package", "ruff")
        uvx_path = shutil.which("uvx")
        for tool, adhoc_cmd in (
            (
                "pybun",
                [pybun_path, "x", package, "--", "--version"] if pybun_path else None,
            ),
            (
                "uvx",
                (
                    [uvx_path, package, "--version"]
                    if uvx_path
                    else (
                        [uv_path, "tool", "run", package, "--version"]
                        if uv_path
                        else None
                    )
                ),
            ),
        ):
            if adhoc_cmd:
                cwd = root / tool / "adhoc"
                cwd.mkdir(parents=True)
                record(
                    "C3_adhoc",
                    tool,
                    adhoc_cmd,
                    count=min(5, iterations),
                    prepare=max(1, warmup),
                    cwd=str(cwd),
                    env={
                        "UV_CACHE_DIR": str(cwd / "uv-cache"),
                        "PYBUN_HOME": str(cwd / "pybun-home"),
                    },
                )

    indexed = {(r.scenario, r.tool): r for r in results}
    comparisons = []
    notes = {
        "C4_startup": "binary startup: pybun --version vs uv --version",
        "C1_warm": "PEP 723 warm cache",
        "C1_cold": "PEP 723 cold cache (network + install included)",
        "C5_resolution": "pybun install vs uv lock (includes preparation)",
    }
    for scenario_id, note in notes.items():
        pybun = indexed.get((scenario_id, "pybun"))
        uv = indexed.get((scenario_id, "uv"))
        if pybun and uv and pybun.success and uv.success:
            comparisons.append(
                build_comparison_row(
                    scenario_id,
                    pybun.duration_ms,
                    pybun.metadata["p95_ms"],
                    uv.duration_ms,
                    uv.metadata["p95_ms"],
                    note,
                )
            )
    if results:
        results[0].metadata.update(
            tool_versions=tool_versions, comparison_table=comparisons
        )
    if comparisons:
        print("\nPyBun vs uv — Comparison Summary")
        print(format_comparison_table(comparisons))
    return results
