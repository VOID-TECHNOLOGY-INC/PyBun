"""
B3: Script Execution Benchmark

Measures script startup time and execution performance.

Scenarios:
- B3.1: Simple script startup time
- B3.2: PEP 723 script (with dependencies)
- B3.3: Heavy import script (many imports)
- B3.4: Profile-based startup (dev/prod)
"""

from __future__ import annotations

import tempfile
from pathlib import Path

# These are injected by bench.py when loading this module
# scenario, BenchResult, find_tool, is_tool_enabled, measure_command


# === Test Scripts ===

SIMPLE_SCRIPT = '''\
#!/usr/bin/env python3
"""Simple hello world script."""
print("Hello, World!")
'''

PEP723_SCRIPT = '''\
#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "requests>=2.28.0",
# ]
# ///
"""PEP 723 script with dependencies."""
import requests
print(f"requests version: {requests.__version__}")
'''

HEAVY_IMPORT_SCRIPT = '''\
#!/usr/bin/env python3
"""Script with many standard library imports."""
import os
import sys
import json
import re
import pathlib
import collections
import functools
import itertools
import datetime
import logging
import typing
import dataclasses
import urllib.parse
import http.client
import email.mime.text

print("All imports successful!")
'''

PROFILE_SCRIPT = '''\
#!/usr/bin/env python3
"""Script to test profile-based execution."""
import os
import sys

profile = os.environ.get("PYBUN_PROFILE", "default")
print(f"Running with profile: {profile}")
print(f"Python: {sys.executable}")
'''


def run_benchmark(config: dict, scenario_config: dict, base_dir: Path) -> list:
    """Run script execution benchmarks."""
    results: list[BenchResult] = []
    
    general = config.get("general", {})
    iterations = general.get("iterations", 5)
    warmup = general.get("warmup", 1)
    dry_run = config.get("dry_run", False)
    verbose = config.get("verbose", False)
    
    # Find tools
    pybun_path = find_tool("pybun", config)
    python_path = find_tool("python3", config) or find_tool("python", config)
    uv_path = find_tool("uv", config) if is_tool_enabled("uv", config) else None
    
    # Create temp directory for test scripts
    with tempfile.TemporaryDirectory(prefix="pybun_bench_") as tmpdir:
        tmp = Path(tmpdir)
        
        # === B3.1: Simple Script Startup ===
        print("\n--- B3.1: Simple Script Startup ---")
        
        simple_script = tmp / "simple.py"
        simple_script.write_text(SIMPLE_SCRIPT)
        
        # Python baseline
        if python_path:
            if dry_run:
                print(f"  Would run: {python_path} {simple_script}")
            else:
                if verbose:
                    print(f"  Running: {python_path} {simple_script}")
                result = measure_command(
                    [python_path, str(simple_script)],
                    warmup=warmup,
                    iterations=iterations,
                )
                result.scenario = "B3.1_simple_startup"
                result.tool = "python"
                results.append(result)
                print(f"  python: {result.duration_ms:.2f}ms")
        
        # PyBun
        if pybun_path:
            if dry_run:
                print(f"  Would run: {pybun_path} run {simple_script}")
            else:
                if verbose:
                    print(f"  Running: {pybun_path} run {simple_script}")
                result = measure_command(
                    [pybun_path, "run", str(simple_script)],
                    warmup=warmup,
                    iterations=iterations,
                )
                result.scenario = "B3.1_simple_startup"
                result.tool = "pybun"
                results.append(result)
                print(f"  pybun: {result.duration_ms:.2f}ms")
        
        # uv
        if uv_path:
            if dry_run:
                print(f"  Would run: {uv_path} run {simple_script}")
            else:
                if verbose:
                    print(f"  Running: {uv_path} run {simple_script}")
                result = measure_command(
                    [uv_path, "run", str(simple_script)],
                    warmup=warmup,
                    iterations=iterations,
                )
                result.scenario = "B3.1_simple_startup"
                result.tool = "uv"
                results.append(result)
                print(f"  uv: {result.duration_ms:.2f}ms")
        
        # === B3.2: PEP 723 Script ===
        if scenario_config.get("pep723", True):
            print("\n--- B3.2: PEP 723 Script (with dependencies) ---")
            
            pep723_script = tmp / "pep723.py"
            pep723_script.write_text(PEP723_SCRIPT)
            
            # PyBun (should handle PEP 723 natively)
            if pybun_path:
                if dry_run:
                    print(f"  Would run: {pybun_path} run {pep723_script}")
                else:
                    if verbose:
                        print(f"  Running: {pybun_path} run {pep723_script}")
                    # First run may install dependencies
                    result = measure_command(
                        [pybun_path, "run", str(pep723_script)],
                        warmup=0,  # No warmup for first run measurement
                        iterations=1,
                    )
                    result.scenario = "B3.2_pep723_cold"
                    result.tool = "pybun"
                    result.metadata["type"] = "cold"
                    results.append(result)
                    print(f"  pybun (cold): {result.duration_ms:.2f}ms")
                    
                    # Warm runs
                    result = measure_command(
                        [pybun_path, "run", str(pep723_script)],
                        warmup=warmup,
                        iterations=iterations,
                    )
                    result.scenario = "B3.2_pep723_warm"
                    result.tool = "pybun"
                    result.metadata["type"] = "warm"
                    results.append(result)
                    print(f"  pybun (warm): {result.duration_ms:.2f}ms")
            
            # uv (also supports PEP 723)
            if uv_path:
                if dry_run:
                    print(f"  Would run: {uv_path} run {pep723_script}")
                else:
                    if verbose:
                        print(f"  Running: {uv_path} run {pep723_script}")
                    # Cold run
                    result = measure_command(
                        [uv_path, "run", str(pep723_script)],
                        warmup=0,
                        iterations=1,
                    )
                    result.scenario = "B3.2_pep723_cold"
                    result.tool = "uv"
                    result.metadata["type"] = "cold"
                    results.append(result)
                    print(f"  uv (cold): {result.duration_ms:.2f}ms")
                    
                    # Warm runs
                    result = measure_command(
                        [uv_path, "run", str(pep723_script)],
                        warmup=warmup,
                        iterations=iterations,
                    )
                    result.scenario = "B3.2_pep723_warm"
                    result.tool = "uv"
                    result.metadata["type"] = "warm"
                    results.append(result)
                    print(f"  uv (warm): {result.duration_ms:.2f}ms")
        
        # === B3.3: Heavy Import Script ===
        print("\n--- B3.3: Heavy Import Script ---")
        
        heavy_script = tmp / "heavy_imports.py"
        heavy_script.write_text(HEAVY_IMPORT_SCRIPT)
        
        # Python baseline
        if python_path:
            if dry_run:
                print(f"  Would run: {python_path} {heavy_script}")
            else:
                result = measure_command(
                    [python_path, str(heavy_script)],
                    warmup=warmup,
                    iterations=iterations,
                )
                result.scenario = "B3.3_heavy_import"
                result.tool = "python"
                results.append(result)
                print(f"  python: {result.duration_ms:.2f}ms")
        
        # PyBun
        if pybun_path:
            if dry_run:
                print(f"  Would run: {pybun_path} run {heavy_script}")
            else:
                result = measure_command(
                    [pybun_path, "run", str(heavy_script)],
                    warmup=warmup,
                    iterations=iterations,
                )
                result.scenario = "B3.3_heavy_import"
                result.tool = "pybun"
                results.append(result)
                print(f"  pybun: {result.duration_ms:.2f}ms")
        
        # uv
        if uv_path:
            if dry_run:
                print(f"  Would run: {uv_path} run {heavy_script}")
            else:
                result = measure_command(
                    [uv_path, "run", str(heavy_script)],
                    warmup=warmup,
                    iterations=iterations,
                )
                result.scenario = "B3.3_heavy_import"
                result.tool = "uv"
                results.append(result)
                print(f"  uv: {result.duration_ms:.2f}ms")
        
        # === B3.4: Profile-based Startup ===
        profiles = scenario_config.get("profiles", ["dev", "prod"])
        if profiles:
            print("\n--- B3.4: Profile-based Startup ---")
            
            profile_script = tmp / "profile_test.py"
            profile_script.write_text(PROFILE_SCRIPT)
            
            if pybun_path:
                for profile in profiles:
                    if dry_run:
                        print(f"  Would run: {pybun_path} run --profile={profile} {profile_script}")
                    else:
                        result = measure_command(
                            [pybun_path, "run", f"--profile={profile}", str(profile_script)],
                            warmup=warmup,
                            iterations=iterations,
                            env={"PYBUN_PROFILE": profile},
                        )
                        result.scenario = f"B3.4_profile_{profile}"
                        result.tool = "pybun"
                        result.metadata["profile"] = profile
                        results.append(result)
                        print(f"  pybun --profile={profile}: {result.duration_ms:.2f}ms")
    
    return results

