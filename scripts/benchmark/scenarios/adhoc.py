"""
B4: Ad-hoc Execution Benchmark

Measures `pybun x` vs `pipx run` vs `uvx` for running tools.

Scenarios:
- B4.1: First run (environment creation included)
- B4.2: Second run (cached)
- B4.3: Version-specified run
"""

from __future__ import annotations

import tempfile
from pathlib import Path

# These are injected by bench.py when loading this module
# scenario, BenchResult, find_tool, is_tool_enabled, measure_command


def adhoc_benchmark(config: dict, scenario_config: dict, base_dir: Path) -> list:
    """Run ad-hoc execution benchmarks."""
    results: list[BenchResult] = []
    
    general = config.get("general", {})
    iterations = general.get("iterations", 5)
    warmup = general.get("warmup", 1)
    dry_run = config.get("dry_run", False)
    verbose = config.get("verbose", False)
    
    # Find tools
    pybun_path = find_tool("pybun", config)
    pipx_path = find_tool("pipx", config) if is_tool_enabled("pipx", config) else None
    uvx_path = find_tool("uvx", config) if is_tool_enabled("uv", config) else None
    # uvx is often just `uv tool run` or standalone `uvx`
    if not uvx_path and is_tool_enabled("uv", config):
        uv_path = find_tool("uv", config)
        if uv_path:
            uvx_path = uv_path  # Will use `uv tool run`
    
    packages = scenario_config.get("packages", ["cowsay", "black", "ruff"])
    
    for package in packages:
        print(f"\n--- Testing package: {package} ---")
        
        # === B4.1: Cold Run (first execution) ===
        print(f"\n  B4.1: Cold Run ({package})")
        
        # For cold run, we need to ensure cache is cleared or use unique temp
        with tempfile.TemporaryDirectory(prefix=f"pybun_x_bench_{package}_") as tmpdir:
            # PyBun
            if pybun_path:
                cmd = [pybun_path, "x", package, "--help"]
                if dry_run:
                    print(f"    Would run: {' '.join(cmd)}")
                else:
                    if verbose:
                        print(f"    Running: {' '.join(cmd)}")
                    result = measure_command(
                        cmd,
                        warmup=0,  # No warmup for cold run
                        iterations=1,
                        env={"PYBUN_X_CACHE": tmpdir},  # Use temp cache
                    )
                    result.scenario = f"B4.1_cold_{package}"
                    result.tool = "pybun"
                    result.metadata["package"] = package
                    result.metadata["type"] = "cold"
                    results.append(result)
                    print(f"    pybun x: {result.duration_ms:.2f}ms")
            
            # pipx
            if pipx_path:
                cmd = [pipx_path, "run", package, "--help"]
                if dry_run:
                    print(f"    Would run: {' '.join(cmd)}")
                else:
                    if verbose:
                        print(f"    Running: {' '.join(cmd)}")
                    result = measure_command(
                        cmd,
                        warmup=0,
                        iterations=1,
                        env={"PIPX_HOME": tmpdir},
                    )
                    result.scenario = f"B4.1_cold_{package}"
                    result.tool = "pipx"
                    result.metadata["package"] = package
                    result.metadata["type"] = "cold"
                    results.append(result)
                    print(f"    pipx run: {result.duration_ms:.2f}ms")
            
            # uvx
            if uvx_path:
                # uvx or uv tool run
                if "uv" in str(uvx_path) and "uvx" not in str(uvx_path):
                    cmd = [uvx_path, "tool", "run", package, "--help"]
                else:
                    cmd = [uvx_path, package, "--help"]
                
                if dry_run:
                    print(f"    Would run: {' '.join(cmd)}")
                else:
                    if verbose:
                        print(f"    Running: {' '.join(cmd)}")
                    result = measure_command(
                        cmd,
                        warmup=0,
                        iterations=1,
                        env={"UV_TOOL_DIR": tmpdir},
                    )
                    result.scenario = f"B4.1_cold_{package}"
                    result.tool = "uvx"
                    result.metadata["package"] = package
                    result.metadata["type"] = "cold"
                    results.append(result)
                    print(f"    uvx: {result.duration_ms:.2f}ms")
        
        # === B4.2: Warm Run (cached) ===
        print(f"\n  B4.2: Warm Run ({package})")
        
        # PyBun
        if pybun_path:
            cmd = [pybun_path, "x", package, "--help"]
            if dry_run:
                print(f"    Would run: {' '.join(cmd)}")
            else:
                if verbose:
                    print(f"    Running: {' '.join(cmd)}")
                result = measure_command(
                    cmd,
                    warmup=warmup,
                    iterations=iterations,
                )
                result.scenario = f"B4.2_warm_{package}"
                result.tool = "pybun"
                result.metadata["package"] = package
                result.metadata["type"] = "warm"
                results.append(result)
                print(f"    pybun x: {result.duration_ms:.2f}ms")
        
        # pipx
        if pipx_path:
            cmd = [pipx_path, "run", package, "--help"]
            if dry_run:
                print(f"    Would run: {' '.join(cmd)}")
            else:
                if verbose:
                    print(f"    Running: {' '.join(cmd)}")
                result = measure_command(
                    cmd,
                    warmup=warmup,
                    iterations=iterations,
                )
                result.scenario = f"B4.2_warm_{package}"
                result.tool = "pipx"
                result.metadata["package"] = package
                result.metadata["type"] = "warm"
                results.append(result)
                print(f"    pipx run: {result.duration_ms:.2f}ms")
        
        # uvx
        if uvx_path:
            if "uv" in str(uvx_path) and "uvx" not in str(uvx_path):
                cmd = [uvx_path, "tool", "run", package, "--help"]
            else:
                cmd = [uvx_path, package, "--help"]
            
            if dry_run:
                print(f"    Would run: {' '.join(cmd)}")
            else:
                if verbose:
                    print(f"    Running: {' '.join(cmd)}")
                result = measure_command(
                    cmd,
                    warmup=warmup,
                    iterations=iterations,
                )
                result.scenario = f"B4.2_warm_{package}"
                result.tool = "uvx"
                result.metadata["package"] = package
                result.metadata["type"] = "warm"
                results.append(result)
                print(f"    uvx: {result.duration_ms:.2f}ms")
    
    # === B4.3: Version-specified Run ===
    print("\n--- B4.3: Version-specified Run ---")
    
    # Test with a specific version of black
    versioned_package = "black==23.12.1"
    
    if pybun_path:
        cmd = [pybun_path, "x", versioned_package, "--help"]
        if dry_run:
            print(f"  Would run: {' '.join(cmd)}")
        else:
            if verbose:
                print(f"  Running: {' '.join(cmd)}")
            result = measure_command(
                cmd,
                warmup=warmup,
                iterations=iterations,
            )
            result.scenario = "B4.3_versioned"
            result.tool = "pybun"
            result.metadata["package"] = versioned_package
            results.append(result)
            print(f"  pybun x {versioned_package}: {result.duration_ms:.2f}ms")
    
    if pipx_path:
        cmd = [pipx_path, "run", versioned_package, "--help"]
        if dry_run:
            print(f"  Would run: {' '.join(cmd)}")
        else:
            if verbose:
                print(f"  Running: {' '.join(cmd)}")
            result = measure_command(
                cmd,
                warmup=warmup,
                iterations=iterations,
            )
            result.scenario = "B4.3_versioned"
            result.tool = "pipx"
            result.metadata["package"] = versioned_package
            results.append(result)
            print(f"  pipx run {versioned_package}: {result.duration_ms:.2f}ms")
    
    if uvx_path:
        if "uv" in str(uvx_path) and "uvx" not in str(uvx_path):
            cmd = [uvx_path, "tool", "run", versioned_package, "--help"]
        else:
            cmd = [uvx_path, versioned_package, "--help"]
        
        if dry_run:
            print(f"  Would run: {' '.join(cmd)}")
        else:
            if verbose:
                print(f"  Running: {' '.join(cmd)}")
            result = measure_command(
                cmd,
                warmup=warmup,
                iterations=iterations,
            )
            result.scenario = "B4.3_versioned"
            result.tool = "uvx"
            result.metadata["package"] = versioned_package
            results.append(result)
            print(f"  uvx {versioned_package}: {result.duration_ms:.2f}ms")
    
    return results

