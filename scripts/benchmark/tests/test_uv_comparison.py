"""Tests for uv_comparison benchmark scenario."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add benchmark root (for bench.py) and scenarios/ (for uv_comparison.py)
_BENCH_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(_BENCH_DIR))
sys.path.insert(0, str(_BENCH_DIR / "scenarios"))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_config():
    return {
        "general": {"iterations": 2, "warmup": 0, "trim_ratio": 0.0, "timeout_seconds": 30},
        "tools": {"pybun": True, "uv": True},
        "paths": {"pybun": "/usr/bin/true"},  # always-success stub
        "scenarios": {
            "uv_comparison": {
                "enabled": True,
                "iterations": 2,
                "warmup": 0,
            }
        },
        "dry_run": False,
        "verbose": False,
    }


@pytest.fixture
def base_dir():
    return Path(__file__).parent.parent


# ---------------------------------------------------------------------------
# Unit: compute_median / compute_percentile
# ---------------------------------------------------------------------------

def test_compute_median_odd():
    from uv_comparison import compute_median
    assert compute_median([3.0, 1.0, 2.0]) == 2.0


def test_compute_median_even():
    from uv_comparison import compute_median
    assert compute_median([4.0, 1.0, 3.0, 2.0]) == 2.5


def test_compute_median_single():
    from uv_comparison import compute_median
    assert compute_median([42.0]) == 42.0


def test_compute_percentile_p50():
    from uv_comparison import compute_percentile
    data = list(range(1, 101))  # 1..100
    # Implementation uses idx = (p/100) * n → 50.0 → floor=50 → s[50]=51, frac=0 → 51.0
    assert compute_percentile(data, 50) == 51.0


def test_compute_percentile_p95():
    from uv_comparison import compute_percentile
    data = list(range(1, 101))
    # idx = 95.0 → s[95]=96, frac=0 → 96.0
    assert compute_percentile(data, 95) == pytest.approx(96.0, rel=0.01)


def test_compute_percentile_empty_returns_zero():
    from uv_comparison import compute_percentile
    assert compute_percentile([], 50) == 0.0


# ---------------------------------------------------------------------------
# Unit: speedup_ratio
# ---------------------------------------------------------------------------

def test_speedup_ratio_faster():
    from uv_comparison import speedup_ratio
    ratio, winner = speedup_ratio(pybun_ms=100.0, uv_ms=200.0)
    assert ratio == pytest.approx(2.0)
    assert winner == "pybun"


def test_speedup_ratio_slower():
    from uv_comparison import speedup_ratio
    ratio, winner = speedup_ratio(pybun_ms=300.0, uv_ms=100.0)
    assert ratio == pytest.approx(3.0)
    assert winner == "uv"


def test_speedup_ratio_parity():
    from uv_comparison import speedup_ratio
    ratio, winner = speedup_ratio(pybun_ms=100.0, uv_ms=100.0)
    assert ratio == pytest.approx(1.0)
    assert winner == "parity"


def test_speedup_ratio_zero_denominator():
    from uv_comparison import speedup_ratio
    ratio, winner = speedup_ratio(pybun_ms=100.0, uv_ms=0.0)
    assert ratio == 0.0
    assert winner == "unknown"


# ---------------------------------------------------------------------------
# Unit: build_comparison_row
# ---------------------------------------------------------------------------

def test_build_comparison_row_pybun_wins():
    from uv_comparison import build_comparison_row
    row = build_comparison_row(
        scenario_id="C4",
        pybun_p50=50.0, pybun_p95=60.0,
        uv_p50=100.0, uv_p95=120.0,
        note="startup test",
    )
    assert row["scenario"] == "C4"
    assert row["pybun_p50_ms"] == 50.0
    assert row["uv_p50_ms"] == 100.0
    assert row["speedup_ratio"] == pytest.approx(2.0)
    assert row["winner"] == "pybun"
    assert row["note"] == "startup test"


def test_build_comparison_row_uv_wins():
    from uv_comparison import build_comparison_row
    row = build_comparison_row(
        scenario_id="C1_cold",
        pybun_p50=500.0, pybun_p95=600.0,
        uv_p50=200.0, uv_p95=250.0,
        note="cold cache",
    )
    assert row["winner"] == "uv"
    assert row["speedup_ratio"] == pytest.approx(2.5)


# ---------------------------------------------------------------------------
# Unit: cv_check (coefficient of variation)
# ---------------------------------------------------------------------------

def test_cv_check_stable():
    from uv_comparison import is_cv_stable
    samples = [100.0, 101.0, 99.0, 100.5, 99.5]
    assert is_cv_stable(samples, threshold=0.15) is True


def test_cv_check_noisy():
    from uv_comparison import is_cv_stable
    samples = [10.0, 200.0, 5.0, 300.0]
    assert is_cv_stable(samples, threshold=0.15) is False


def test_cv_check_single_sample():
    from uv_comparison import is_cv_stable
    assert is_cv_stable([42.0], threshold=0.15) is True


def test_cv_check_empty():
    from uv_comparison import is_cv_stable
    assert is_cv_stable([], threshold=0.15) is True


# ---------------------------------------------------------------------------
# Unit: format_comparison_table (Markdown output)
# ---------------------------------------------------------------------------

def test_format_comparison_table_contains_headers():
    from uv_comparison import format_comparison_table
    rows = [
        {
            "scenario": "C4",
            "pybun_p50_ms": 10.0,
            "uv_p50_ms": 15.0,
            "speedup_ratio": 1.5,
            "winner": "pybun",
            "note": "startup",
        }
    ]
    table = format_comparison_table(rows)
    assert "| Scenario |" in table
    assert "Winner" in table
    assert "pybun" in table
    assert "C4" in table


def test_format_comparison_table_empty():
    from uv_comparison import format_comparison_table
    table = format_comparison_table([])
    assert "| Scenario |" in table  # header still present


# ---------------------------------------------------------------------------
# Integration: C4 startup benchmark (dry run with /usr/bin/true)
# ---------------------------------------------------------------------------

def test_c4_startup_dry_run_produces_results(monkeypatch):
    """C4 should produce BenchResult objects for both tools."""
    # Import the module and inject bench stubs
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "uv_comparison",
        Path(__file__).parent.parent / "scenarios" / "uv_comparison.py",
    )
    mod = importlib.util.module_from_spec(spec)

    # Provide minimal stubs matching bench.py injection contract
    from bench import BenchResult, find_tool, is_tool_enabled, measure_command, measure_with_hyperfine, scenario
    mod.scenario = scenario
    mod.BenchResult = BenchResult
    mod.find_tool = find_tool
    mod.is_tool_enabled = is_tool_enabled
    mod.measure_command = measure_command
    mod.measure_with_hyperfine = measure_with_hyperfine

    spec.loader.exec_module(mod)

    config = {
        "general": {"iterations": 1, "warmup": 0, "trim_ratio": 0.0, "timeout_seconds": 10},
        "tools": {"pybun": True, "uv": True},
        "paths": {
            "pybun": "/usr/bin/true",
            "uv": "/usr/bin/true",
        },
        "scenarios": {"uv_comparison": {"enabled": True}},
        "dry_run": False,
        "verbose": False,
    }
    scenario_config = config["scenarios"]["uv_comparison"]
    base_dir = Path(__file__).parent.parent

    # Keep every discovered executable local and inert, including uvx and hyperfine.
    monkeypatch.setattr(mod.shutil, "which", lambda _name: None)
    results = mod.uv_comparison_benchmark(config, scenario_config, base_dir)

    assert {(r.scenario, r.tool) for r in results if r.scenario == "C4_startup"} == {
        ("C4_startup", "pybun"), ("C4_startup", "uv"),
    }
    assert any(r.scenario == "C3_adhoc" and r.tool == "uvx" for r in results)
    for r in results:
        assert hasattr(r, "scenario")
        assert hasattr(r, "tool")
        assert hasattr(r, "duration_ms")


# ---------------------------------------------------------------------------
# Integration: JSON report structure
# ---------------------------------------------------------------------------

def test_report_has_comparison_key():
    """The scenario function should attach comparison data to metadata."""
    from uv_comparison import build_comparison_row
    row = build_comparison_row("C4", 10.0, 12.0, 15.0, 18.0, "test")
    assert "scenario" in row
    assert "speedup_ratio" in row
    assert "winner" in row
    assert "pybun_p50_ms" in row
    assert "uv_p50_ms" in row


@pytest.mark.parametrize("mode", ["nonzero", "timeout", "missing", "warmup"])
def test_failed_commands_are_not_comparisons(tmp_path, monkeypatch, mode):
    import bench
    bench.load_scenarios(_BENCH_DIR)
    scenario = bench.SCENARIOS["uv_comparison"]
    stub = tmp_path / "pybun"
    state = tmp_path / "seen"
    stub.write_text(
        f"#!{sys.executable}\n"
        "import sys,time\nfrom pathlib import Path\n"
        "if sys.argv[1:] == ['--version']: print('pybun test'); sys.exit(0)\n"
        + ({
            "nonzero": "print('stdout-only-failure');sys.exit(7)\n",
            "timeout": "print('before-timeout',flush=True);time.sleep(10)\n",
            "missing": "print('unused')\n",
            "warmup": f"p=Path({str(state)!r}); seen=p.exists();p.touch(); print('warmup-failure');sys.exit(0 if seen else 8)\n",
        }[mode])
    )
    stub.chmod(0o755)
    # Neither discover nor invoke a real uvx during this test.
    monkeypatch.setattr(bench.shutil, "which", lambda _: None)
    if mode == "missing":
        # find_tool checks existence; simulate an executable removed after discovery.
        monkeypatch.setitem(scenario.__globals__, "find_tool", lambda tool, config: str(tmp_path / "missing") if tool == "pybun" else "/usr/bin/true")
    config = {
        "general": {"iterations": 1, "warmup": 1, "timeout_seconds": 0.1 if mode == "timeout" else 10},
        "paths": {"pybun": str(stub), "uv": "/usr/bin/true"},
    }
    results = scenario(config, {}, _BENCH_DIR)
    failed = [r for r in results if not r.success]
    assert failed
    if mode in {"nonzero", "timeout", "missing"}:
        assert {r.scenario for r in failed} >= {"C1_warm", "C1_cold", "C5_resolution", "C3_adhoc"}
    assert all(r.error for r in failed)
    if mode == "nonzero":
        assert all('stdout-only-failure' in r.error for r in failed)
    comparisons = results[0].metadata.get("comparison_table", [])
    failed_scenarios = {r.scenario for r in failed}
    assert not any(row["scenario"] in failed_scenarios for row in comparisons)
    assert not list(_BENCH_DIR.glob("fixtures/pep723.py.lock"))


def test_benchmark_cli_reports_failure_and_exits_nonzero(tmp_path):
    import subprocess
    stub = tmp_path / 'pybun'
    stub.write_text(f"#!{sys.executable}\nimport sys\nprint('probe-failure')\nsys.exit(0 if sys.argv[1:] == ['--version'] else 7)\n")
    stub.chmod(0o755)
    # Ensure optional uvx discovery also resolves to an inert executable.
    (tmp_path / 'uvx').symlink_to('/usr/bin/true')
    config = tmp_path / 'config.toml'
    config.write_text(f'[general]\niterations=1\nwarmup=0\ntimeout_seconds=10\n[paths]\npybun="{stub}"\nuv="/usr/bin/true"\n[scenarios.uv_comparison]\niterations=1\nwarmup=0\n')
    import os
    env = dict(os.environ, PATH=str(tmp_path))
    output = tmp_path / 'results'
    run = subprocess.run([sys.executable, str(_BENCH_DIR / 'bench.py'), '-s', 'uv_comparison', '--config', str(config), '--format', 'json', '-o', str(output)], capture_output=True, text=True, env=env)
    assert run.returncode == 1, run.stdout + run.stderr
    report = json.loads(next(output.glob('benchmark_*.json')).read_text())
    assert report['summary']['failed'] >= 4
    assert any('probe-failure' in (r.get('error') or '') for r in report['results'])


def test_c3_passes_tool_flags_after_separator(tmp_path, monkeypatch):
    import bench
    bench.load_scenarios(_BENCH_DIR)
    stub = tmp_path / "pybun"
    stub.write_text(
        f"#!{sys.executable}\nimport sys\n"
        "if sys.argv[1:2] == ['x'] and sys.argv[1:] != ['x','ruff','--','--version']: sys.exit(2)\n"
    )
    stub.chmod(0o755)
    monkeypatch.setattr(bench.shutil, "which", lambda _: None)
    config = {
        "general": {"iterations": 1, "warmup": 0},
        "paths": {"pybun": str(stub), "uv": "/usr/bin/true"},
    }
    results = bench.SCENARIOS["uv_comparison"](config, {}, _BENCH_DIR)
    assert next(r for r in results if r.scenario == "C3_adhoc" and r.tool == "pybun").success
