"""
B5: Module Finding Benchmark

Measures `pybun module-find` vs Python standard import.

Scenarios:
- B5.1: Standard library module search
- B5.2: Third-party package search
- B5.3: Large directory scan
- B5.4: Cache hit rate
"""

from __future__ import annotations

import tempfile
from pathlib import Path

# These are injected by bench.py when loading this module
# scenario, BenchResult, find_tool, measure_command


# Python script to measure import time
IMPORT_TIMER_SCRIPT = '''\
#!/usr/bin/env python3
"""Measure import time for a module."""
import sys
import time

module_name = sys.argv[1] if len(sys.argv) > 1 else "os"

start = time.perf_counter_ns()
try:
    __import__(module_name)
    success = True
except ImportError:
    success = False
end = time.perf_counter_ns()

elapsed_us = (end - start) / 1000  # Convert to microseconds
print(f"{elapsed_us:.2f}")
'''

# Python script to scan and import multiple modules
BATCH_IMPORT_SCRIPT = '''\
#!/usr/bin/env python3
"""Measure batch import time."""
import sys
import time

modules = sys.argv[1].split(",") if len(sys.argv) > 1 else ["os"]

results = []
for module_name in modules:
    start = time.perf_counter_ns()
    try:
        __import__(module_name)
        success = True
    except ImportError:
        success = False
    end = time.perf_counter_ns()
    elapsed_us = (end - start) / 1000
    results.append(f"{module_name}:{elapsed_us:.2f}")

print(",".join(results))
'''


def module_find_benchmark(config: dict, scenario_config: dict, base_dir: Path) -> list:
    """Run module finding benchmarks."""
    results: list[BenchResult] = []
    
    general = config.get("general", {})
    iterations = general.get("iterations", 5)
    warmup = general.get("warmup", 1)
    trim_ratio = scenario_config.get("trim_ratio", general.get("trim_ratio", 0.0))
    dry_run = config.get("dry_run", False)
    verbose = config.get("verbose", False)
    
    # Find tools
    pybun_path = find_tool("pybun", config)
    python_path = find_tool("python3", config) or find_tool("python", config)
    
    modules = scenario_config.get("modules", ["os", "json", "requests", "numpy", "pandas"])
    
    with tempfile.TemporaryDirectory(prefix="pybun_module_bench_") as tmpdir:
        tmp = Path(tmpdir)
        
        # Create timer script
        timer_script = tmp / "import_timer.py"
        timer_script.write_text(IMPORT_TIMER_SCRIPT)
        
        batch_script = tmp / "batch_import.py"
        batch_script.write_text(BATCH_IMPORT_SCRIPT)
        
        # === B5.1: Standard Library Module Search ===
        print("\n--- B5.1: Standard Library Module Search ---")
        
        stdlib_modules = ["os", "sys", "json", "re", "pathlib", "collections", "functools"]
        
        for module in stdlib_modules:
            # Python import
            if python_path:
                if dry_run:
                    print(f"  Would run: {python_path} {timer_script} {module}")
                else:
                    if verbose:
                        print(f"  Running: {python_path} {timer_script} {module}")
                    result = measure_command(
                        [python_path, str(timer_script), module],
                        warmup=warmup,
                        iterations=iterations,
                        trim_ratio=trim_ratio,
                    )
                    result.scenario = f"B5.1_stdlib_{module}"
                    result.tool = "python_import"
                    result.metadata["module"] = module
                    result.metadata["type"] = "stdlib"
                    results.append(result)
                    print(f"  python import {module}: {result.duration_ms:.2f}ms")
            
            # PyBun module-find
            if pybun_path:
                if dry_run:
                    print(f"  Would run: {pybun_path} module-find {module}")
                else:
                    if verbose:
                        print(f"  Running: {pybun_path} module-find {module}")
                    result = measure_command(
                        [pybun_path, "module-find", module],
                        warmup=warmup,
                        iterations=iterations,
                        trim_ratio=trim_ratio,
                    )
                    result.scenario = f"B5.1_stdlib_{module}"
                    result.tool = "pybun"
                    result.metadata["module"] = module
                    result.metadata["type"] = "stdlib"
                    results.append(result)
                    print(f"  pybun module-find {module}: {result.duration_ms:.2f}ms")
        
        # === B5.2: Third-party Package Search ===
        print("\n--- B5.2: Third-party Package Search ---")
        
        third_party = ["requests", "numpy", "pandas", "flask", "django"]
        
        for module in third_party:
            # Only test if module might be installed
            if pybun_path:
                if dry_run:
                    print(f"  Would run: {pybun_path} module-find {module}")
                else:
                    if verbose:
                        print(f"  Running: {pybun_path} module-find {module}")
                    result = measure_command(
                        [pybun_path, "module-find", module],
                        warmup=warmup,
                        iterations=iterations,
                        trim_ratio=trim_ratio,
                    )
                    result.scenario = f"B5.2_thirdparty_{module}"
                    result.tool = "pybun"
                    result.metadata["module"] = module
                    result.metadata["type"] = "third_party"
                    results.append(result)
                    status = "✓" if result.success else "✗ (not found)"
                    print(f"  pybun module-find {module}: {result.duration_ms:.2f}ms {status}")
        
        # === B5.3: Large Directory Scan ===
        if scenario_config.get("benchmark_parallel", True):
            print("\n--- B5.3: Large Directory Scan ---")
            
            # Create a fake package directory with many files
            fake_pkg = tmp / "fake_package"
            fake_pkg.mkdir()
            (fake_pkg / "__init__.py").write_text("# Fake package")
            
            # Create many submodules
            for i in range(100):
                (fake_pkg / f"module_{i:03d}.py").write_text(f"# Module {i}")
            
            if pybun_path:
                if dry_run:
                    print(f"  Would run: {pybun_path} module-find --scan {fake_pkg}")
                else:
                    if verbose:
                        print(f"  Running: {pybun_path} module-find --scan {fake_pkg}")
                    result = measure_command(
                        [pybun_path, "module-find", "--scan", str(fake_pkg)],
                        warmup=warmup,
                        iterations=iterations,
                        trim_ratio=trim_ratio,
                    )
                    result.scenario = "B5.3_large_scan"
                    result.tool = "pybun"
                    result.metadata["file_count"] = 101  # 100 modules + __init__
                    results.append(result)
                    print(f"  pybun --scan (100 files): {result.duration_ms:.2f}ms")
            
            # Compare with Python glob
            if python_path:
                scan_script = tmp / "glob_scan.py"
                scan_script.write_text(f'''\
import glob
import time
start = time.perf_counter_ns()
files = glob.glob("{fake_pkg}/**/*.py", recursive=True)
end = time.perf_counter_ns()
print(f"{{len(files)}} files in {{(end-start)/1e6:.2f}}ms")
''')
                if dry_run:
                    print(f"  Would run: {python_path} {scan_script}")
                else:
                    result = measure_command(
                        [python_path, str(scan_script)],
                        warmup=warmup,
                        iterations=iterations,
                        trim_ratio=trim_ratio,
                    )
                    result.scenario = "B5.3_large_scan"
                    result.tool = "python_glob"
                    result.metadata["file_count"] = 101
                    results.append(result)
                    print(f"  python glob (100 files): {result.duration_ms:.2f}ms")
        
        # === B5.4: Cache Hit Rate ===
        print("\n--- B5.4: Cache Hit Rate ---")
        
        if pybun_path:
            # First run (cache miss)
            if dry_run:
                print(f"  Would run: {pybun_path} module-find os (cold)")
            else:
                result = measure_command(
                    [pybun_path, "module-find", "os"],
                    warmup=0,
                    iterations=1,
                    trim_ratio=trim_ratio,
                )
                result.scenario = "B5.4_cache_cold"
                result.tool = "pybun"
                result.metadata["cache"] = "cold"
                results.append(result)
                print(f"  pybun module-find os (cold): {result.duration_ms:.2f}ms")
            
            # Second run (cache hit)
            if dry_run:
                print(f"  Would run: {pybun_path} module-find os (warm)")
            else:
                result = measure_command(
                    [pybun_path, "module-find", "os"],
                    warmup=warmup,
                    iterations=iterations,
                    trim_ratio=trim_ratio,
                )
                result.scenario = "B5.4_cache_warm"
                result.tool = "pybun"
                result.metadata["cache"] = "warm"
                results.append(result)
                print(f"  pybun module-find os (warm): {result.duration_ms:.2f}ms")
            
            # With --benchmark flag
            if dry_run:
                print(f"  Would run: {pybun_path} module-find --benchmark os")
            else:
                result = measure_command(
                    [pybun_path, "module-find", "--benchmark", "os"],
                    warmup=warmup,
                    iterations=iterations,
                    trim_ratio=trim_ratio,
                )
                result.scenario = "B5.4_benchmark_mode"
                result.tool = "pybun"
                result.metadata["mode"] = "benchmark"
                results.append(result)
                print(f"  pybun module-find --benchmark os: {result.duration_ms:.2f}ms")
    
    return results
