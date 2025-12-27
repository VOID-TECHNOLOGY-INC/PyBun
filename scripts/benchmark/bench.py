#!/usr/bin/env python3
"""
PyBun Benchmark Runner

Usage:
    python bench.py                     # Run all scenarios
    python bench.py -s run              # Run specific scenario
    python bench.py -s run,adhoc        # Run multiple scenarios
    python bench.py --list              # List available scenarios
    python bench.py -o results/         # Specify output directory
    python bench.py --format markdown   # Output format (json, markdown, csv)
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

# Try to import tomllib (Python 3.11+) or fall back to toml
try:
    import tomllib
except ImportError:
    try:
        import toml as tomllib  # type: ignore
    except ImportError:
        print("Error: Please install toml package: pip install toml")
        sys.exit(1)


# === Data Classes ===

@dataclass
class SystemInfo:
    """System information for benchmark context."""
    os: str
    os_version: str
    architecture: str
    cpu: str
    cpu_count: int
    memory_gb: float
    python_version: str
    timestamp: str

    @classmethod
    def collect(cls) -> "SystemInfo":
        """Collect current system information."""
        import platform
        
        # Try to get CPU info
        cpu = platform.processor() or "Unknown"
        if sys.platform == "darwin":
            try:
                result = subprocess.run(
                    ["sysctl", "-n", "machdep.cpu.brand_string"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    cpu = result.stdout.strip()
            except Exception:
                pass
        
        # Get memory (platform-specific)
        memory_gb = 0.0
        if sys.platform == "darwin":
            try:
                result = subprocess.run(
                    ["sysctl", "-n", "hw.memsize"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    memory_gb = int(result.stdout.strip()) / (1024**3)
            except Exception:
                pass
        elif sys.platform == "linux":
            try:
                with open("/proc/meminfo") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            kb = int(line.split()[1])
                            memory_gb = kb / (1024**2)
                            break
            except Exception:
                pass
        
        return cls(
            os=platform.system(),
            os_version=platform.release(),
            architecture=platform.machine(),
            cpu=cpu,
            cpu_count=os.cpu_count() or 1,
            memory_gb=round(memory_gb, 1),
            python_version=platform.python_version(),
            timestamp=datetime.now(timezone.utc).isoformat(),
        )


@dataclass
class BenchResult:
    """Single benchmark result."""
    scenario: str
    tool: str
    duration_ms: float
    memory_mb: float = 0.0
    success: bool = True
    iterations: int = 1
    min_ms: float = 0.0
    max_ms: float = 0.0
    stddev_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class BenchReport:
    """Complete benchmark report."""
    meta: dict
    results: list[BenchResult]
    summary: dict

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "meta": self.meta,
            "results": [r.to_dict() for r in self.results],
            "summary": self.summary,
        }


# === Utilities ===

def find_tool(name: str, config: dict) -> str | None:
    """Find tool path from config or PATH."""
    # Check config first
    paths = config.get("paths", {})
    if name in paths and paths[name]:
        path = paths[name]
        if os.path.exists(path):
            return path
    
    # Check PATH
    path = shutil.which(name)
    return path


def is_tool_enabled(name: str, config: dict) -> bool:
    """Check if tool is enabled in config."""
    tools = config.get("tools", {})
    return tools.get(name, False)


def trim_samples(samples: list[float], trim_ratio: float) -> list[float]:
    """Trim outliers from samples by removing a ratio from each tail."""
    if trim_ratio <= 0 or not samples:
        return samples
    trim_n = int(len(samples) * trim_ratio)
    if trim_n == 0 or (trim_n * 2) >= len(samples):
        return samples
    sorted_samples = sorted(samples)
    return sorted_samples[trim_n:-trim_n]


def compute_stats(samples: list[float], trim_ratio: float = 0.0) -> tuple[float, float, float, float, int]:
    """Compute mean/min/max/stddev with optional trimming."""
    import statistics

    if not samples:
        return 0.0, 0.0, 0.0, 0.0, 0

    trimmed = trim_samples(samples, trim_ratio)
    if not trimmed:
        trimmed = samples

    avg = statistics.mean(trimmed)
    min_t = min(trimmed)
    max_t = max(trimmed)
    stddev = statistics.stdev(trimmed) if len(trimmed) > 1 else 0.0
    return avg, min_t, max_t, stddev, len(trimmed)


def measure_command(
    cmd: list[str],
    warmup: int = 1,
    iterations: int = 5,
    timeout: int = 300,
    env: dict | None = None,
    cwd: str | None = None,
    trim_ratio: float = 0.0,
) -> BenchResult:
    """
    Execute command multiple times and measure performance.
    
    Returns BenchResult with timing statistics.
    """
    # Prepare environment
    run_env = os.environ.copy()
    if env:
        run_env.update(env)
    
    # Warmup runs
    for _ in range(warmup):
        try:
            subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                env=run_env,
                cwd=cwd,
            )
        except Exception:
            pass
    
    # Timed runs
    times: list[float] = []
    success = True
    last_error = None
    
    for _ in range(iterations):
        start = time.perf_counter()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                env=run_env,
                cwd=cwd,
            )
            end = time.perf_counter()
            
            if result.returncode != 0:
                success = False
                last_error = result.stderr.decode("utf-8", errors="replace")[:500]
            
            times.append((end - start) * 1000)  # Convert to ms
            
        except subprocess.TimeoutExpired:
            success = False
            last_error = f"Timeout after {timeout}s"
            times.append(timeout * 1000)
        except Exception as e:
            success = False
            last_error = str(e)
    
    # Calculate statistics
    avg, min_t, max_t, stddev, trimmed_count = compute_stats(times, trim_ratio)

    result = BenchResult(
        scenario="",  # Will be set by caller
        tool=cmd[0] if cmd else "unknown",
        duration_ms=round(avg, 2),
        min_ms=round(min_t, 2),
        max_ms=round(max_t, 2),
        stddev_ms=round(stddev, 2),
        iterations=iterations,
        success=success,
        error=last_error if not success else None,
    )
    if trim_ratio > 0 and trimmed_count:
        result.metadata["trim_ratio"] = trim_ratio
        result.metadata["trimmed_iterations"] = trimmed_count
    return result


def measure_with_hyperfine(
    cmd: list[str],
    warmup: int = 1,
    iterations: int = 5,
    hyperfine_path: str | None = None,
) -> BenchResult | None:
    """
    Use hyperfine for more accurate benchmarking.
    Returns None if hyperfine is not available.
    """
    hp = hyperfine_path or shutil.which("hyperfine")
    if not hp:
        return None
    
    try:
        result = subprocess.run(
            [
                hp,
                "--warmup", str(warmup),
                "--runs", str(iterations),
                "--export-json", "/dev/stdout",
                "--",
                *cmd,
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        
        if result.returncode == 0:
            data = json.loads(result.stdout)
            bench = data["results"][0]
            return BenchResult(
                scenario="",
                tool=cmd[0] if cmd else "unknown",
                duration_ms=bench["mean"] * 1000,
                min_ms=bench["min"] * 1000,
                max_ms=bench["max"] * 1000,
                stddev_ms=bench["stddev"] * 1000,
                iterations=iterations,
                success=True,
            )
    except Exception:
        pass
    
    return None


# === Scenario Registry ===

SCENARIOS: dict[str, Callable] = {}


def scenario(name: str):
    """Decorator to register a benchmark scenario."""
    def decorator(func: Callable):
        SCENARIOS[name] = func
        return func
    return decorator


def run_scenario(name: str, config: dict, base_dir: Path) -> list[BenchResult]:
    """Run a single scenario and return results."""
    if name not in SCENARIOS:
        print(f"Unknown scenario: {name}")
        return []
    
    scenario_config = config.get("scenarios", {}).get(name, {})
    if not scenario_config.get("enabled", True):
        print(f"Scenario '{name}' is disabled in config")
        return []
    
    print(f"\n{'='*60}")
    print(f"Running scenario: {name}")
    print(f"{'='*60}")
    
    return SCENARIOS[name](config, scenario_config, base_dir)


# === Import Scenarios ===

def load_scenarios(base_dir: Path):
    """Dynamically load scenario modules and register their benchmark functions."""
    import importlib.util
    
    scenarios_dir = base_dir / "scenarios"
    if not scenarios_dir.exists():
        return
    
    # Scenario name mapping (file name -> scenario function name)
    scenario_func_names = {
        "run": "run_benchmark",
        "adhoc": "adhoc_benchmark",
        "module_find": "module_find_benchmark",
        "resolution": "resolution_benchmark",
        "install": "install_benchmark",
        "lazy_import": "lazy_import_benchmark",
        "test": "test_benchmark",
        "mcp": "mcp_benchmark",
    }
    
    for py_file in scenarios_dir.glob("*.py"):
        if py_file.name.startswith("_") or py_file.name.startswith("."):
            continue
        
        scenario_name = py_file.stem
        
        try:
            # Load module using importlib.util to avoid import path issues
            spec = importlib.util.spec_from_file_location(
                f"scenarios.{scenario_name}",
                py_file,
            )
            if spec is None or spec.loader is None:
                continue
            
            module = importlib.util.module_from_spec(spec)
            
            # Inject bench module's exports into the scenario module
            module.scenario = scenario
            module.BenchResult = BenchResult
            module.find_tool = find_tool
            module.is_tool_enabled = is_tool_enabled
            module.measure_command = measure_command
            module.measure_with_hyperfine = measure_with_hyperfine
            
            spec.loader.exec_module(module)
            
            # Get the benchmark function
            func_name = scenario_func_names.get(scenario_name, f"{scenario_name}_benchmark")
            if hasattr(module, func_name):
                SCENARIOS[scenario_name] = getattr(module, func_name)
            
        except Exception as e:
            print(f"Warning: Failed to load scenario {py_file.name}: {e}")


# === Report Generation ===

def generate_summary(results: list[BenchResult]) -> dict:
    """Generate summary statistics from results."""
    if not results:
        return {}
    
    # Group by scenario
    by_scenario: dict[str, list[BenchResult]] = {}
    for r in results:
        by_scenario.setdefault(r.scenario, []).append(r)
    
    # Calculate wins/losses for pybun
    pybun_wins = 0
    pybun_losses = 0
    speedups: list[float] = []
    
    for scenario, scenario_results in by_scenario.items():
        pybun_result = next((r for r in scenario_results if r.tool == "pybun"), None)
        if not pybun_result:
            continue
        
        for r in scenario_results:
            if r.tool == "pybun" or not r.success:
                continue
            
            if pybun_result.duration_ms < r.duration_ms:
                pybun_wins += 1
                if r.duration_ms > 0:
                    speedups.append(r.duration_ms / pybun_result.duration_ms)
            else:
                pybun_losses += 1
                if pybun_result.duration_ms > 0:
                    speedups.append(r.duration_ms / pybun_result.duration_ms)
    
    avg_speedup = sum(speedups) / len(speedups) if speedups else 1.0
    
    return {
        "total_scenarios": len(by_scenario),
        "total_benchmarks": len(results),
        "pybun_wins": pybun_wins,
        "pybun_losses": pybun_losses,
        "average_speedup": round(avg_speedup, 2),
        "successful": sum(1 for r in results if r.success),
        "failed": sum(1 for r in results if not r.success),
    }


def save_json_report(report: BenchReport, output_path: Path):
    """Save report as JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report.to_dict(), f, indent=2)
    print(f"JSON report saved to: {output_path}")


def save_markdown_report(report: BenchReport, output_path: Path):
    """Save report as Markdown."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    lines = [
        "# PyBun Benchmark Report",
        "",
        f"Generated: {report.meta.get('timestamp', 'unknown')}",
        "",
        "## System Information",
        "",
    ]
    
    sys_info = report.meta.get("system", {})
    if sys_info:
        lines.extend([
            f"- **OS**: {sys_info.get('os', 'unknown')} {sys_info.get('os_version', '')}",
            f"- **CPU**: {sys_info.get('cpu', 'unknown')} ({sys_info.get('cpu_count', 0)} cores)",
            f"- **Memory**: {sys_info.get('memory_gb', 0)} GB",
            f"- **Python**: {sys_info.get('python_version', 'unknown')}",
            "",
        ])
    
    lines.extend([
        "## Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
    ])
    
    summary = report.summary
    lines.extend([
        f"| Total Scenarios | {summary.get('total_scenarios', 0)} |",
        f"| Total Benchmarks | {summary.get('total_benchmarks', 0)} |",
        f"| PyBun Wins | {summary.get('pybun_wins', 0)} |",
        f"| PyBun Losses | {summary.get('pybun_losses', 0)} |",
        f"| Average Speedup | {summary.get('average_speedup', 1.0)}x |",
        "",
    ])
    
    # Group results by scenario
    by_scenario: dict[str, list[BenchResult]] = {}
    for r in report.results:
        by_scenario.setdefault(r.scenario, []).append(r)
    
    lines.append("## Detailed Results")
    lines.append("")
    
    for scenario, results in sorted(by_scenario.items()):
        lines.extend([
            f"### {scenario}",
            "",
            "| Tool | Duration (ms) | Min | Max | StdDev | Status |",
            "|------|--------------|-----|-----|--------|--------|",
        ])
        
        for r in sorted(results, key=lambda x: x.duration_ms):
            status = "✅" if r.success else "❌"
            lines.append(
                f"| {r.tool} | {r.duration_ms:.2f} | {r.min_ms:.2f} | {r.max_ms:.2f} | {r.stddev_ms:.2f} | {status} |"
            )
        
        lines.append("")
    
    with open(output_path, "w") as f:
        f.write("\n".join(lines))
    
    print(f"Markdown report saved to: {output_path}")


def save_csv_report(report: BenchReport, output_path: Path):
    """Save report as CSV."""
    import csv
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    fieldnames = [
        "scenario", "tool", "duration_ms", "min_ms", "max_ms",
        "stddev_ms", "iterations", "success", "error"
    ]
    
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for r in report.results:
            writer.writerow({
                "scenario": r.scenario,
                "tool": r.tool,
                "duration_ms": r.duration_ms,
                "min_ms": r.min_ms,
                "max_ms": r.max_ms,
                "stddev_ms": r.stddev_ms,
                "iterations": r.iterations,
                "success": r.success,
                "error": r.error or "",
            })
    
    print(f"CSV report saved to: {output_path}")


# === Main Entry Point ===

def main():
    parser = argparse.ArgumentParser(
        description="PyBun Benchmark Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "-s", "--scenario",
        help="Comma-separated list of scenarios to run (default: all)",
    )
    parser.add_argument(
        "-o", "--output",
        default="results",
        help="Output directory for results (default: results)",
    )
    parser.add_argument(
        "--format",
        choices=["json", "markdown", "csv", "all"],
        default="json",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--config",
        default="config.toml",
        help="Config file path (default: config.toml)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available scenarios",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        help="Override number of iterations",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        help="Override number of warmup runs",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands without executing",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output",
    )
    
    args = parser.parse_args()
    
    # Determine base directory
    base_dir = Path(__file__).parent.resolve()
    
    # Load scenarios
    load_scenarios(base_dir)
    
    # List scenarios if requested
    if args.list:
        print("Available scenarios:")
        for name in sorted(SCENARIOS.keys()):
            print(f"  - {name}")
        return 0
    
    # Load config
    config_path = base_dir / args.config
    if config_path.exists():
        with open(config_path, "rb") as f:
            config = tomllib.load(f)
    else:
        print(f"Warning: Config file not found: {config_path}")
        config = {}
    
    # Override from args
    general = config.setdefault("general", {})
    if args.iterations:
        general["iterations"] = args.iterations
    if args.warmup:
        general["warmup"] = args.warmup
    
    # Store dry-run flag
    config["dry_run"] = args.dry_run
    config["verbose"] = args.verbose
    
    # Determine scenarios to run
    if args.scenario:
        scenario_names = [s.strip() for s in args.scenario.split(",")]
    else:
        scenario_names = list(SCENARIOS.keys())
    
    # Collect system info
    sys_info = SystemInfo.collect()
    
    print("=" * 60)
    print("PyBun Benchmark Runner")
    print("=" * 60)
    print(f"System: {sys_info.os} {sys_info.os_version} ({sys_info.architecture})")
    print(f"CPU: {sys_info.cpu}")
    print(f"Python: {sys_info.python_version}")
    print(f"Scenarios: {', '.join(scenario_names)}")
    print("=" * 60)
    
    # Run scenarios
    all_results: list[BenchResult] = []
    
    for name in scenario_names:
        try:
            results = run_scenario(name, config, base_dir)
            all_results.extend(results)
        except Exception as e:
            print(f"Error running scenario '{name}': {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
    
    # Generate report
    summary = generate_summary(all_results)
    report = BenchReport(
        meta={
            "pybun_version": "0.1.0",
            "timestamp": sys_info.timestamp,
            "system": asdict(sys_info),
        },
        results=all_results,
        summary=summary,
    )
    
    # Save reports
    output_dir = base_dir / args.output
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    formats = ["json", "markdown", "csv"] if args.format == "all" else [args.format]
    
    for fmt in formats:
        if fmt == "json":
            save_json_report(report, output_dir / f"benchmark_{timestamp}.json")
        elif fmt == "markdown":
            save_markdown_report(report, output_dir / f"benchmark_{timestamp}.md")
        elif fmt == "csv":
            save_csv_report(report, output_dir / f"benchmark_{timestamp}.csv")
    
    # Print summary
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"Total benchmarks: {summary.get('total_benchmarks', 0)}")
    print(f"Successful: {summary.get('successful', 0)}")
    print(f"Failed: {summary.get('failed', 0)}")
    print(f"PyBun wins: {summary.get('pybun_wins', 0)}")
    print(f"PyBun losses: {summary.get('pybun_losses', 0)}")
    print(f"Average speedup: {summary.get('average_speedup', 1.0):.2f}x")
    
    return 0 if summary.get('failed', 0) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
