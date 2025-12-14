"""
B7: Test Execution Benchmark

Measures test discovery and execution performance.

Scenarios:
- B7.1: Test discovery time
- B7.2: Small test suite execution
- B7.3: Parallel execution (shard)
- B7.4: AST discovery vs pytest discovery
"""

from __future__ import annotations

import tempfile
from pathlib import Path

# These are injected by bench.py when loading this module
# scenario, BenchResult, find_tool, is_tool_enabled, measure_command


# Sample test files
SIMPLE_TEST_FILE = '''\
"""Simple test file."""
import pytest

def test_addition():
    assert 1 + 1 == 2

def test_subtraction():
    assert 5 - 3 == 2

def test_multiplication():
    assert 2 * 3 == 6

def test_division():
    assert 10 / 2 == 5

class TestMath:
    def test_power(self):
        assert 2 ** 3 == 8
    
    def test_modulo(self):
        assert 10 % 3 == 1
'''

MEDIUM_TEST_FILE = '''\
"""Medium test file with fixtures."""
import pytest

@pytest.fixture
def sample_data():
    return {"name": "test", "value": 42}

@pytest.fixture
def sample_list():
    return [1, 2, 3, 4, 5]

def test_data_name(sample_data):
    assert sample_data["name"] == "test"

def test_data_value(sample_data):
    assert sample_data["value"] == 42

def test_list_length(sample_list):
    assert len(sample_list) == 5

def test_list_sum(sample_list):
    assert sum(sample_list) == 15

@pytest.mark.parametrize("value,expected", [
    (1, 1),
    (2, 4),
    (3, 9),
    (4, 16),
])
def test_square(value, expected):
    assert value ** 2 == expected

class TestStrings:
    def test_upper(self):
        assert "hello".upper() == "HELLO"
    
    def test_lower(self):
        assert "HELLO".lower() == "hello"
    
    def test_strip(self):
        assert "  hello  ".strip() == "hello"
'''


def create_test_suite(tmp: Path, num_files: int = 10, tests_per_file: int = 10) -> Path:
    """Create a test suite with specified number of files and tests."""
    tests_dir = tmp / "tests"
    tests_dir.mkdir(exist_ok=True)
    
    for i in range(num_files):
        test_file = tests_dir / f"test_module_{i:03d}.py"
        tests = []
        tests.append('"""Auto-generated test file."""')
        tests.append("import pytest")
        tests.append("")
        
        for j in range(tests_per_file):
            tests.append(f"def test_function_{j:03d}():")
            tests.append(f"    assert {j} == {j}")
            tests.append("")
        
        test_file.write_text("\n".join(tests))
    
    return tests_dir


def test_benchmark(config: dict, scenario_config: dict, base_dir: Path) -> list:
    """Run test execution benchmarks."""
    results: list[BenchResult] = []
    
    general = config.get("general", {})
    iterations = general.get("iterations", 5)
    warmup = general.get("warmup", 1)
    dry_run = config.get("dry_run", False)
    verbose = config.get("verbose", False)
    
    # Find tools
    pybun_path = find_tool("pybun", config)
    pytest_path = find_tool("pytest", config)
    python_path = find_tool("python3", config) or find_tool("python", config)
    
    parallel_workers = scenario_config.get("parallel_workers", [1, 2, 4])
    
    with tempfile.TemporaryDirectory(prefix="pybun_test_bench_") as tmpdir:
        tmp = Path(tmpdir)
        
        # Create test files
        tests_dir = tmp / "tests"
        tests_dir.mkdir()
        
        (tests_dir / "test_simple.py").write_text(SIMPLE_TEST_FILE)
        (tests_dir / "test_medium.py").write_text(MEDIUM_TEST_FILE)
        
        # === B7.1: Test Discovery Time ===
        print("\n--- B7.1: Test Discovery Time ---")
        
        # Create a larger test suite for discovery
        large_tests_dir = create_test_suite(tmp / "large", num_files=20, tests_per_file=10)
        
        # PyBun discovery
        if pybun_path:
            cmd = [pybun_path, "test", "--discover", str(large_tests_dir), "--format=json"]
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
                result.scenario = "B7.1_discovery"
                result.tool = "pybun"
                result.metadata["test_files"] = 20
                result.metadata["tests_per_file"] = 10
                results.append(result)
                print(f"  pybun --discover: {result.duration_ms:.2f}ms")
        
        # pytest --collect-only
        if pytest_path:
            cmd = [pytest_path, "--collect-only", "-q", str(large_tests_dir)]
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
                result.scenario = "B7.1_discovery"
                result.tool = "pytest"
                result.metadata["test_files"] = 20
                result.metadata["tests_per_file"] = 10
                results.append(result)
                print(f"  pytest --collect-only: {result.duration_ms:.2f}ms")
        
        # === B7.2: Small Test Suite Execution ===
        print("\n--- B7.2: Small Test Suite Execution ---")
        
        # PyBun test
        if pybun_path:
            cmd = [pybun_path, "test", str(tests_dir), "--format=json"]
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
                result.scenario = "B7.2_small_suite"
                result.tool = "pybun"
                results.append(result)
                print(f"  pybun test: {result.duration_ms:.2f}ms")
        
        # pytest
        if pytest_path:
            cmd = [pytest_path, str(tests_dir), "-q"]
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
                result.scenario = "B7.2_small_suite"
                result.tool = "pytest"
                results.append(result)
                print(f"  pytest: {result.duration_ms:.2f}ms")
        
        # unittest
        if python_path:
            # Create unittest-compatible tests
            unittest_dir = tmp / "unittest_tests"
            unittest_dir.mkdir()
            (unittest_dir / "test_simple.py").write_text('''\
import unittest

class TestSimple(unittest.TestCase):
    def test_add(self):
        self.assertEqual(1 + 1, 2)
    
    def test_sub(self):
        self.assertEqual(5 - 3, 2)

if __name__ == "__main__":
    unittest.main()
''')
            
            cmd = [python_path, "-m", "unittest", "discover", "-s", str(unittest_dir), "-q"]
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
                result.scenario = "B7.2_small_suite"
                result.tool = "unittest"
                results.append(result)
                print(f"  unittest: {result.duration_ms:.2f}ms")
        
        # === B7.3: Parallel Execution (Shard) ===
        print("\n--- B7.3: Parallel Execution (Shard) ---")
        
        for workers in parallel_workers:
            if pybun_path:
                cmd = [pybun_path, "test", str(large_tests_dir), f"--shard=1/{workers}", "--format=json"]
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
                    result.scenario = f"B7.3_parallel_{workers}"
                    result.tool = "pybun"
                    result.metadata["workers"] = workers
                    results.append(result)
                    print(f"  pybun --shard=1/{workers}: {result.duration_ms:.2f}ms")
        
        # pytest-xdist comparison (if installed)
        if pytest_path:
            # Check if pytest-xdist is available
            import subprocess
            check = subprocess.run([pytest_path, "--version"], capture_output=True, text=True)
            has_xdist = "xdist" in check.stdout.lower() or "xdist" in check.stderr.lower()
            
            if has_xdist:
                for workers in parallel_workers:
                    cmd = [pytest_path, str(large_tests_dir), "-n", str(workers), "-q"]
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
                        result.scenario = f"B7.3_parallel_{workers}"
                        result.tool = "pytest-xdist"
                        result.metadata["workers"] = workers
                        results.append(result)
                        print(f"  pytest -n {workers}: {result.duration_ms:.2f}ms")
        
        # === B7.4: AST Discovery vs pytest Discovery ===
        print("\n--- B7.4: AST Discovery vs pytest Discovery ---")
        
        if pybun_path:
            # Native AST discovery
            cmd = [pybun_path, "test", "--discover", str(large_tests_dir), "--format=json"]
            if dry_run:
                print(f"  Would run: {' '.join(cmd)}")
            else:
                result = measure_command(
                    cmd,
                    warmup=warmup,
                    iterations=iterations,
                )
                result.scenario = "B7.4_ast_vs_pytest"
                result.tool = "pybun_ast"
                results.append(result)
                print(f"  pybun AST discovery: {result.duration_ms:.2f}ms")
            
            # pytest-compat mode
            cmd = [pybun_path, "test", "--discover", "--pytest-compat", str(large_tests_dir), "--format=json"]
            if dry_run:
                print(f"  Would run: {' '.join(cmd)}")
            else:
                result = measure_command(
                    cmd,
                    warmup=warmup,
                    iterations=iterations,
                )
                result.scenario = "B7.4_ast_vs_pytest"
                result.tool = "pybun_pytest_compat"
                results.append(result)
                print(f"  pybun --pytest-compat: {result.duration_ms:.2f}ms")
    
    return results

