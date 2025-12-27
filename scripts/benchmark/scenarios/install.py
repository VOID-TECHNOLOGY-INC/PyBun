"""
B2: Package Installation Benchmark

Measures package installation performance.

Scenarios:
- B2.1: Cold install (no cache)
- B2.2: Warm install (cached)
- B2.3: Large project install
- B2.4: Parallel installation efficiency
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

# These are injected by bench.py when loading this module
# scenario, BenchResult, find_tool, is_tool_enabled, measure_command


SIMPLE_REQUIREMENTS = """\
requests>=2.28.0
click>=8.0.0
rich>=13.0.0
"""

MEDIUM_REQUIREMENTS = """\
requests>=2.28.0
click>=8.0.0
pydantic>=2.0.0
httpx>=0.24.0
rich>=13.0.0
typer>=0.9.0
python-dotenv>=1.0.0
aiohttp>=3.8.0
fastapi>=0.100.0
uvicorn>=0.23.0
"""

LARGE_REQUIREMENTS = """\
requests>=2.28.0
click>=8.0.0
pydantic>=2.0.0
httpx>=0.24.0
rich>=13.0.0
typer>=0.9.0
python-dotenv>=1.0.0
aiohttp>=3.8.0
fastapi>=0.100.0
uvicorn>=0.23.0
sqlalchemy>=2.0.0
alembic>=1.11.0
celery>=5.3.0
redis>=4.6.0
boto3>=1.28.0
pytest>=7.4.0
pytest-cov>=4.1.0
black>=23.7.0
ruff>=0.0.280
mypy>=1.4.0
jinja2>=3.1.0
pyyaml>=6.0.0
toml>=0.10.0
orjson>=3.9.0
msgpack>=1.0.0
websockets>=11.0.0
starlette>=0.27.0
anyio>=3.7.0
tenacity>=8.2.0
structlog>=23.1.0
"""


def install_benchmark(config: dict, scenario_config: dict, base_dir: Path) -> list:
    """Run package installation benchmarks."""
    results: list[BenchResult] = []
    
    general = config.get("general", {})
    iterations = general.get("iterations", 5)
    warmup = general.get("warmup", 1)
    trim_ratio = scenario_config.get("trim_ratio", general.get("trim_ratio", 0.0))
    dry_run = config.get("dry_run", False)
    verbose = config.get("verbose", False)
    
    # Find tools
    pybun_path = find_tool("pybun", config)
    uv_path = find_tool("uv", config) if is_tool_enabled("uv", config) else None
    pip_path = find_tool("pip", config) if is_tool_enabled("pip", config) else None
    
    cold_cache = scenario_config.get("cold_cache", True)
    warm_cache = scenario_config.get("warm_cache", True)
    
    # === B2.1: Cold Install ===
    if cold_cache:
        print("\n--- B2.1: Cold Install (no cache) ---")
        
        with tempfile.TemporaryDirectory(prefix="pybun_install_cold_") as tmpdir:
            tmp = Path(tmpdir)
            venv_dir = tmp / "venv"
            requirements = tmp / "requirements.txt"
            requirements.write_text(SIMPLE_REQUIREMENTS)
            
            # Create fresh venv for each tool
            python_path = find_tool("python3", config) or find_tool("python", config)
            
            # uv (usually fastest)
            if uv_path:
                test_venv = tmp / "uv_venv"
                cmd = [uv_path, "venv", str(test_venv)]
                if not dry_run:
                    import subprocess
                    subprocess.run(cmd, capture_output=True)
                
                cmd = [
                    uv_path, "pip", "install",
                    "-r", str(requirements),
                    "--python", str(test_venv / "bin" / "python"),
                    "--no-cache",
                ]
                if dry_run:
                    print(f"  Would run: {' '.join(cmd)}")
                else:
                    if verbose:
                        print(f"  Running: {' '.join(cmd)}")
                    result = measure_command(
                        cmd,
                        warmup=0,  # No warmup for cold
                        iterations=1,
                        trim_ratio=trim_ratio,
                        cwd=str(tmp),
                    )
                    result.scenario = "B2.1_cold_install"
                    result.tool = "uv"
                    results.append(result)
                    print(f"  uv pip install (cold): {result.duration_ms:.2f}ms")
            
            # pip
            if pip_path:
                test_venv = tmp / "pip_venv"
                if python_path and not dry_run:
                    import subprocess
                    subprocess.run([python_path, "-m", "venv", str(test_venv)], capture_output=True)
                
                pip_in_venv = test_venv / "bin" / "pip"
                if pip_in_venv.exists():
                    cmd = [str(pip_in_venv), "install", "-r", str(requirements), "--no-cache-dir"]
                    if dry_run:
                        print(f"  Would run: {' '.join(cmd)}")
                    else:
                        if verbose:
                            print(f"  Running: {' '.join(cmd)}")
                        result = measure_command(
                            cmd,
                            warmup=0,
                            iterations=1,
                            trim_ratio=trim_ratio,
                            cwd=str(tmp),
                        )
                        result.scenario = "B2.1_cold_install"
                        result.tool = "pip"
                        results.append(result)
                        print(f"  pip install (cold): {result.duration_ms:.2f}ms")
    
    # === B2.2: Warm Install ===
    if warm_cache:
        print("\n--- B2.2: Warm Install (cached) ---")
        
        with tempfile.TemporaryDirectory(prefix="pybun_install_warm_") as tmpdir:
            tmp = Path(tmpdir)
            requirements = tmp / "requirements.txt"
            requirements.write_text(SIMPLE_REQUIREMENTS)
            
            python_path = find_tool("python3", config) or find_tool("python", config)
            
            # uv (with cache)
            if uv_path:
                test_venv = tmp / "uv_venv"
                if not dry_run:
                    import subprocess
                    subprocess.run([uv_path, "venv", str(test_venv)], capture_output=True)
                    # Prime the cache
                    subprocess.run([
                        uv_path, "pip", "install",
                        "-r", str(requirements),
                        "--python", str(test_venv / "bin" / "python"),
                    ], capture_output=True)
                
                # Measure warm install
                test_venv2 = tmp / "uv_venv2"
                if not dry_run:
                    subprocess.run([uv_path, "venv", str(test_venv2)], capture_output=True)
                
                cmd = [
                    uv_path, "pip", "install",
                    "-r", str(requirements),
                    "--python", str(test_venv2 / "bin" / "python"),
                ]
                if dry_run:
                    print(f"  Would run: {' '.join(cmd)}")
                else:
                    if verbose:
                        print(f"  Running: {' '.join(cmd)}")
                    result = measure_command(
                        cmd,
                        warmup=warmup,
                        iterations=iterations,
                        trim_ratio=trim_ratio,
                        cwd=str(tmp),
                    )
                    result.scenario = "B2.2_warm_install"
                    result.tool = "uv"
                    results.append(result)
                    print(f"  uv pip install (warm): {result.duration_ms:.2f}ms")
            
            # pip (with cache)
            if pip_path and python_path:
                test_venv = tmp / "pip_venv"
                if not dry_run:
                    import subprocess
                    subprocess.run([python_path, "-m", "venv", str(test_venv)], capture_output=True)
                
                pip_in_venv = test_venv / "bin" / "pip"
                if pip_in_venv.exists():
                    cmd = [str(pip_in_venv), "install", "-r", str(requirements)]
                    if dry_run:
                        print(f"  Would run: {' '.join(cmd)}")
                    else:
                        if verbose:
                            print(f"  Running: {' '.join(cmd)}")
                        result = measure_command(
                            cmd,
                            warmup=warmup,
                            iterations=iterations,
                            trim_ratio=trim_ratio,
                            cwd=str(tmp),
                        )
                        result.scenario = "B2.2_warm_install"
                        result.tool = "pip"
                        results.append(result)
                        print(f"  pip install (warm): {result.duration_ms:.2f}ms")
    
    # === B2.3: Large Project Install ===
    print("\n--- B2.3: Large Project Install ---")
    
    with tempfile.TemporaryDirectory(prefix="pybun_install_large_") as tmpdir:
        tmp = Path(tmpdir)
        requirements = tmp / "requirements.txt"
        requirements.write_text(LARGE_REQUIREMENTS)
        
        python_path = find_tool("python3", config) or find_tool("python", config)
        
        # uv
        if uv_path:
            test_venv = tmp / "uv_venv"
            if not dry_run:
                import subprocess
                subprocess.run([uv_path, "venv", str(test_venv)], capture_output=True)
            
            cmd = [
                uv_path, "pip", "install",
                "-r", str(requirements),
                "--python", str(test_venv / "bin" / "python"),
            ]
            if dry_run:
                print(f"  Would run: {' '.join(cmd)}")
            else:
                if verbose:
                    print(f"  Running: {' '.join(cmd)}")
                result = measure_command(
                    cmd,
                    warmup=0,
                    iterations=1,  # Large install, single run
                    trim_ratio=trim_ratio,
                    cwd=str(tmp),
                )
                result.scenario = "B2.3_large_install"
                result.tool = "uv"
                result.metadata["package_count"] = len(LARGE_REQUIREMENTS.strip().split("\n"))
                results.append(result)
                print(f"  uv pip install (large): {result.duration_ms:.2f}ms")
        
        # pip
        if pip_path and python_path:
            test_venv = tmp / "pip_venv"
            if not dry_run:
                import subprocess
                subprocess.run([python_path, "-m", "venv", str(test_venv)], capture_output=True)
            
            pip_in_venv = test_venv / "bin" / "pip"
            if pip_in_venv.exists():
                cmd = [str(pip_in_venv), "install", "-r", str(requirements)]
                if dry_run:
                    print(f"  Would run: {' '.join(cmd)}")
                else:
                    if verbose:
                        print(f"  Running: {' '.join(cmd)}")
                    result = measure_command(
                        cmd,
                        warmup=0,
                        iterations=1,
                        trim_ratio=trim_ratio,
                        cwd=str(tmp),
                    )
                    result.scenario = "B2.3_large_install"
                    result.tool = "pip"
                    result.metadata["package_count"] = len(LARGE_REQUIREMENTS.strip().split("\n"))
                    results.append(result)
                    print(f"  pip install (large): {result.duration_ms:.2f}ms")
    
    return results
