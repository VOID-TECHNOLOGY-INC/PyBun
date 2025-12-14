"""
B1: Dependency Resolution Benchmark

Measures dependency resolution performance.

Scenarios:
- B1.1: Single package (requests)
- B1.2: Medium project (10 packages)
- B1.3: Large project (50+ packages, deep dependencies)
- B1.4: Conflict resolution (version constraints)
- B1.5: Cached re-resolution
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

# These are injected by bench.py when loading this module
# scenario, BenchResult, find_tool, is_tool_enabled, measure_command


# Sample pyproject.toml templates
SINGLE_PACKAGE_PYPROJECT = '''\
[project]
name = "bench-single"
version = "0.1.0"
requires-python = ">=3.9"
dependencies = [
    "requests>=2.28.0",
]
'''

MEDIUM_PROJECT_PYPROJECT = '''\
[project]
name = "bench-medium"
version = "0.1.0"
requires-python = ">=3.9"
dependencies = [
    "requests>=2.28.0",
    "click>=8.0.0",
    "pydantic>=2.0.0",
    "httpx>=0.24.0",
    "rich>=13.0.0",
    "typer>=0.9.0",
    "python-dotenv>=1.0.0",
    "aiohttp>=3.8.0",
    "fastapi>=0.100.0",
    "uvicorn>=0.23.0",
]
'''

LARGE_PROJECT_PYPROJECT = '''\
[project]
name = "bench-large"
version = "0.1.0"
requires-python = ">=3.9"
dependencies = [
    "requests>=2.28.0",
    "click>=8.0.0",
    "pydantic>=2.0.0",
    "httpx>=0.24.0",
    "rich>=13.0.0",
    "typer>=0.9.0",
    "python-dotenv>=1.0.0",
    "aiohttp>=3.8.0",
    "fastapi>=0.100.0",
    "uvicorn>=0.23.0",
    "sqlalchemy>=2.0.0",
    "alembic>=1.11.0",
    "celery>=5.3.0",
    "redis>=4.6.0",
    "boto3>=1.28.0",
    "pandas>=2.0.0",
    "numpy>=1.24.0",
    "scipy>=1.11.0",
    "scikit-learn>=1.3.0",
    "matplotlib>=3.7.0",
    "pillow>=10.0.0",
    "pytest>=7.4.0",
    "pytest-cov>=4.1.0",
    "pytest-asyncio>=0.21.0",
    "black>=23.7.0",
    "ruff>=0.0.280",
    "mypy>=1.4.0",
    "pre-commit>=3.3.0",
    "sphinx>=7.0.0",
    "mkdocs>=1.5.0",
    "jinja2>=3.1.0",
    "pyyaml>=6.0.0",
    "toml>=0.10.0",
    "cryptography>=41.0.0",
    "bcrypt>=4.0.0",
    "pyjwt>=2.8.0",
    "httptools>=0.6.0",
    "orjson>=3.9.0",
    "msgpack>=1.0.0",
    "protobuf>=4.23.0",
    "grpcio>=1.56.0",
    "websockets>=11.0.0",
    "starlette>=0.27.0",
    "anyio>=3.7.0",
    "trio>=0.22.0",
    "tenacity>=8.2.0",
    "structlog>=23.1.0",
    "sentry-sdk>=1.28.0",
    "prometheus-client>=0.17.0",
    "opentelemetry-api>=1.19.0",
]
'''

CONFLICT_PYPROJECT = '''\
[project]
name = "bench-conflict"
version = "0.1.0"
requires-python = ">=3.9"
dependencies = [
    "requests>=2.28.0,<2.30.0",
    "urllib3>=1.26.0,<2.0.0",
]
'''


def resolution_benchmark(config: dict, scenario_config: dict, base_dir: Path) -> list:
    """Run dependency resolution benchmarks."""
    results: list[BenchResult] = []
    
    general = config.get("general", {})
    iterations = general.get("iterations", 5)
    warmup = general.get("warmup", 1)
    dry_run = config.get("dry_run", False)
    verbose = config.get("verbose", False)
    
    # Find tools
    pybun_path = find_tool("pybun", config)
    uv_path = find_tool("uv", config) if is_tool_enabled("uv", config) else None
    pip_path = find_tool("pip", config) if is_tool_enabled("pip", config) else None
    poetry_path = find_tool("poetry", config) if is_tool_enabled("poetry", config) else None
    
    fixtures = scenario_config.get("fixtures", ["small", "medium", "large"])
    
    fixture_map = {
        "small": ("B1.1", SINGLE_PACKAGE_PYPROJECT, "single package"),
        "medium": ("B1.2", MEDIUM_PROJECT_PYPROJECT, "10 packages"),
        "large": ("B1.3", LARGE_PROJECT_PYPROJECT, "50+ packages"),
    }
    
    for fixture_name in fixtures:
        if fixture_name not in fixture_map:
            continue
        
        scenario_id, pyproject_content, description = fixture_map[fixture_name]
        print(f"\n--- {scenario_id}: {description} ---")
        
        with tempfile.TemporaryDirectory(prefix=f"pybun_resolve_bench_{fixture_name}_") as tmpdir:
            tmp = Path(tmpdir)
            pyproject = tmp / "pyproject.toml"
            pyproject.write_text(pyproject_content)
            
            # PyBun resolve
            if pybun_path:
                cmd = [pybun_path, "install", "--dry-run", "--format=json"]
                if dry_run:
                    print(f"  Would run: {' '.join(cmd)}")
                else:
                    if verbose:
                        print(f"  Running: {' '.join(cmd)}")
                    result = measure_command(
                        cmd,
                        warmup=warmup,
                        iterations=iterations,
                        cwd=str(tmp),
                    )
                    result.scenario = f"{scenario_id}_resolution"
                    result.tool = "pybun"
                    result.metadata["fixture"] = fixture_name
                    results.append(result)
                    print(f"  pybun: {result.duration_ms:.2f}ms")
            
            # uv pip compile
            if uv_path:
                # Create requirements.in for uv
                req_in = tmp / "requirements.in"
                # Extract dependencies from pyproject
                lines = []
                in_deps = False
                for line in pyproject_content.split("\n"):
                    if "dependencies = [" in line:
                        in_deps = True
                        continue
                    if in_deps:
                        if "]" in line:
                            break
                        # Extract dependency
                        dep = line.strip().strip('",')
                        if dep:
                            lines.append(dep)
                req_in.write_text("\n".join(lines))
                
                cmd = [uv_path, "pip", "compile", str(req_in), "-o", "/dev/null", "--quiet"]
                if dry_run:
                    print(f"  Would run: {' '.join(cmd)}")
                else:
                    if verbose:
                        print(f"  Running: {' '.join(cmd)}")
                    result = measure_command(
                        cmd,
                        warmup=warmup,
                        iterations=iterations,
                        cwd=str(tmp),
                    )
                    result.scenario = f"{scenario_id}_resolution"
                    result.tool = "uv"
                    result.metadata["fixture"] = fixture_name
                    results.append(result)
                    print(f"  uv: {result.duration_ms:.2f}ms")
            
            # pip-compile (if pip-tools installed)
            pip_compile = find_tool("pip-compile", config)
            if pip_compile:
                req_in = tmp / "requirements.in"
                if not req_in.exists():
                    lines = []
                    in_deps = False
                    for line in pyproject_content.split("\n"):
                        if "dependencies = [" in line:
                            in_deps = True
                            continue
                        if in_deps:
                            if "]" in line:
                                break
                            dep = line.strip().strip('",')
                            if dep:
                                lines.append(dep)
                    req_in.write_text("\n".join(lines))
                
                cmd = [pip_compile, str(req_in), "-o", "/dev/null", "--quiet"]
                if dry_run:
                    print(f"  Would run: {' '.join(cmd)}")
                else:
                    if verbose:
                        print(f"  Running: {' '.join(cmd)}")
                    result = measure_command(
                        cmd,
                        warmup=warmup,
                        iterations=iterations,
                        cwd=str(tmp),
                    )
                    result.scenario = f"{scenario_id}_resolution"
                    result.tool = "pip-compile"
                    result.metadata["fixture"] = fixture_name
                    results.append(result)
                    print(f"  pip-compile: {result.duration_ms:.2f}ms")
            
            # poetry lock (slow, optional)
            if poetry_path:
                # Poetry needs a different pyproject format
                poetry_pyproject = tmp / "pyproject.toml"
                # Convert to poetry format (simplified)
                poetry_content = pyproject_content.replace("[project]", "[tool.poetry]")
                poetry_content = poetry_content.replace("requires-python", "python")
                poetry_pyproject.write_text(poetry_content)
                
                cmd = [poetry_path, "lock", "--no-update"]
                if dry_run:
                    print(f"  Would run: {' '.join(cmd)}")
                else:
                    if verbose:
                        print(f"  Running: {' '.join(cmd)}")
                    result = measure_command(
                        cmd,
                        warmup=0,  # Poetry lock is slow
                        iterations=1,
                        cwd=str(tmp),
                    )
                    result.scenario = f"{scenario_id}_resolution"
                    result.tool = "poetry"
                    result.metadata["fixture"] = fixture_name
                    results.append(result)
                    print(f"  poetry: {result.duration_ms:.2f}ms")
    
    # === B1.4: Conflict Resolution ===
    print("\n--- B1.4: Conflict Resolution ---")
    
    with tempfile.TemporaryDirectory(prefix="pybun_resolve_conflict_") as tmpdir:
        tmp = Path(tmpdir)
        pyproject = tmp / "pyproject.toml"
        pyproject.write_text(CONFLICT_PYPROJECT)
        
        if pybun_path:
            cmd = [pybun_path, "install", "--dry-run", "--format=json"]
            if dry_run:
                print(f"  Would run: {' '.join(cmd)}")
            else:
                result = measure_command(
                    cmd,
                    warmup=warmup,
                    iterations=iterations,
                    cwd=str(tmp),
                )
                result.scenario = "B1.4_conflict"
                result.tool = "pybun"
                results.append(result)
                print(f"  pybun: {result.duration_ms:.2f}ms")
        
        if uv_path:
            req_in = tmp / "requirements.in"
            req_in.write_text("requests>=2.28.0,<2.30.0\nurllib3>=1.26.0,<2.0.0")
            
            cmd = [uv_path, "pip", "compile", str(req_in), "-o", "/dev/null", "--quiet"]
            if dry_run:
                print(f"  Would run: {' '.join(cmd)}")
            else:
                result = measure_command(
                    cmd,
                    warmup=warmup,
                    iterations=iterations,
                    cwd=str(tmp),
                )
                result.scenario = "B1.4_conflict"
                result.tool = "uv"
                results.append(result)
                print(f"  uv: {result.duration_ms:.2f}ms")
    
    # === B1.5: Cached Re-resolution ===
    print("\n--- B1.5: Cached Re-resolution ---")
    
    with tempfile.TemporaryDirectory(prefix="pybun_resolve_cache_") as tmpdir:
        tmp = Path(tmpdir)
        pyproject = tmp / "pyproject.toml"
        pyproject.write_text(MEDIUM_PROJECT_PYPROJECT)
        
        if pybun_path:
            # First run (cold)
            cmd = [pybun_path, "install", "--dry-run", "--format=json"]
            if dry_run:
                print(f"  Would run: {' '.join(cmd)} (cold)")
            else:
                result = measure_command(
                    cmd,
                    warmup=0,
                    iterations=1,
                    cwd=str(tmp),
                )
                result.scenario = "B1.5_cached_cold"
                result.tool = "pybun"
                results.append(result)
                print(f"  pybun (cold): {result.duration_ms:.2f}ms")
            
            # Second run (warm)
            if dry_run:
                print(f"  Would run: {' '.join(cmd)} (warm)")
            else:
                result = measure_command(
                    cmd,
                    warmup=warmup,
                    iterations=iterations,
                    cwd=str(tmp),
                )
                result.scenario = "B1.5_cached_warm"
                result.tool = "pybun"
                results.append(result)
                print(f"  pybun (warm): {result.duration_ms:.2f}ms")
    
    return results

