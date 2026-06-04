import os
import sys
import shutil
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# scenarios/run.py depends on bench.py injecting these names at load time.
# Inject stubs before importing so the module is importable in tests.
import bench
import importlib
import types

# Load run module with injected bench exports (mirrors bench.load_scenarios)
run_spec = importlib.util.spec_from_file_location(
    "scenarios.run",
    Path(__file__).resolve().parents[1] / "scenarios" / "run.py",
)
run_module = importlib.util.module_from_spec(run_spec)  # type: ignore[arg-type]
run_module.scenario = lambda name: (lambda fn: fn)  # noqa: E731
run_module.BenchResult = bench.BenchResult
run_module.find_tool = bench.find_tool
run_module.is_tool_enabled = bench.is_tool_enabled
run_module.measure_command = bench.measure_command
run_module.measure_with_hyperfine = bench.measure_with_hyperfine
run_spec.loader.exec_module(run_module)  # type: ignore[union-attr]

run_scenario = run_module


class TestRunScenario(unittest.TestCase):
    def test_resolve_pep723_script_default(self) -> None:
        base_dir = Path(__file__).resolve().parents[1]
        script = run_scenario.resolve_pep723_script(base_dir, {})
        self.assertTrue(script.exists())
        self.assertTrue(str(script).endswith("fixtures/pep723.py"))


def _make_fake_binary(path: Path) -> Path:
    path.write_text("#!/bin/sh\nexit 0")
    path.chmod(0o755)
    return path


def _collect_calls(config: dict, scenario_config: dict, base_dir: Path) -> list[dict]:
    """Run run_benchmark with patched measure_command and return captured calls."""
    calls: list[dict] = []

    def fake_measure(cmd, warmup=1, iterations=5, timeout=300, env=None, cwd=None, trim_ratio=0.0):
        calls.append({"cmd": list(cmd), "cwd": cwd})
        return bench.BenchResult(
            scenario="",
            tool=cmd[0] if cmd else "unknown",
            duration_ms=1.0,
            success=True,
        )

    original = run_scenario.measure_command
    run_scenario.measure_command = fake_measure
    try:
        run_scenario.run_benchmark(config, scenario_config, base_dir)
    finally:
        run_scenario.measure_command = original

    return calls


class TestRunCwdHermetic(unittest.TestCase):
    """All measure_command calls in run_benchmark must specify cwd."""

    def setUp(self) -> None:
        import tempfile
        self._bindir_ctx = tempfile.TemporaryDirectory()
        self.bindir = Path(self._bindir_ctx.__enter__())
        self.fake_pybun = _make_fake_binary(self.bindir / "pybun")
        self.fake_uv = _make_fake_binary(self.bindir / "uv")
        self.fake_python = _make_fake_binary(self.bindir / "python3")
        self.base_dir = Path(__file__).resolve().parents[1]

    def tearDown(self) -> None:
        self._bindir_ctx.__exit__(None, None, None)

    def _make_config(self, *, pep723: bool = False, profiles: list | None = None) -> tuple[dict, dict]:
        config = {
            "_base_dir": str(self.base_dir),
            "paths": {
                "pybun": str(self.fake_pybun),
                "uv": str(self.fake_uv),
                "python3": str(self.fake_python),
            },
            "tools": {"uv": True, "python": True},
            "general": {"iterations": 1, "warmup": 0},
            "dry_run": False,
            "verbose": False,
        }
        scenario_config = {
            "pep723": pep723,
            "profiles": profiles if profiles is not None else [],
            "pep723_clear_envs": False,
            "pep723_clear_fs_cache": False,
        }
        return config, scenario_config

    def test_b31_uv_run_has_cwd(self) -> None:
        """B3.1: uv run must pass cwd so it doesn't walk up to a parent pyproject.toml."""
        config, scenario_config = self._make_config()
        calls = _collect_calls(config, scenario_config, self.base_dir)

        uv_run_calls = [c for c in calls if "uv" in c["cmd"][0] and "run" in c["cmd"]]
        self.assertTrue(len(uv_run_calls) > 0, f"No uv run calls found. All calls: {calls}")
        for call in uv_run_calls:
            self.assertIsNotNone(call["cwd"], f"uv run missing cwd: {call['cmd']}")

    def test_b33_uv_run_has_cwd(self) -> None:
        """B3.3: uv run for heavy import script must pass cwd."""
        config, scenario_config = self._make_config()
        calls = _collect_calls(config, scenario_config, self.base_dir)

        # B3.3 uses heavy_imports.py — collect all uv calls
        uv_calls = [c for c in calls if "uv" in c["cmd"][0]]
        self.assertTrue(len(uv_calls) > 0)
        for call in uv_calls:
            self.assertIsNotNone(call["cwd"], f"uv call missing cwd: {call['cmd']}")

    def test_all_measure_command_calls_have_cwd(self) -> None:
        """Every single measure_command call must specify cwd."""
        config, scenario_config = self._make_config()
        calls = _collect_calls(config, scenario_config, self.base_dir)

        self.assertGreater(len(calls), 0, "Expected at least one measure_command call")
        for call in calls:
            self.assertIsNotNone(
                call["cwd"],
                f"measure_command missing cwd for cmd: {call['cmd']}"
            )

    def test_pybun_run_has_cwd(self) -> None:
        """pybun run calls must also pass cwd."""
        config, scenario_config = self._make_config()
        calls = _collect_calls(config, scenario_config, self.base_dir)

        pybun_calls = [c for c in calls if "pybun" in c["cmd"][0]]
        self.assertTrue(len(pybun_calls) > 0, f"No pybun calls found. All: {calls}")
        for call in pybun_calls:
            self.assertIsNotNone(call["cwd"], f"pybun call missing cwd: {call['cmd']}")

    def test_python_run_has_cwd(self) -> None:
        """python run calls must also pass cwd."""
        config, scenario_config = self._make_config()
        calls = _collect_calls(config, scenario_config, self.base_dir)

        python_calls = [c for c in calls if "python" in c["cmd"][0]]
        self.assertTrue(len(python_calls) > 0, f"No python calls found. All: {calls}")
        for call in python_calls:
            self.assertIsNotNone(call["cwd"], f"python call missing cwd: {call['cmd']}")


class TestFindToolRelativePath(unittest.TestCase):
    """find_tool must resolve relative paths against _base_dir, not cwd."""

    def test_relative_path_resolved_against_base_dir(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            bin_dir = tmp / "bin"
            bin_dir.mkdir()
            fake_pybun = _make_fake_binary(bin_dir / "pybun")

            config = {
                "_base_dir": str(tmp),
                "paths": {"pybun": "bin/pybun"},
            }

            original_cwd = os.getcwd()
            try:
                os.chdir("/tmp")
                result = bench.find_tool("pybun", config)
            finally:
                os.chdir(original_cwd)

            self.assertEqual(result, str(fake_pybun))

    def test_relative_path_without_base_dir_falls_through_to_which(self) -> None:
        config = {
            "paths": {"nonexistent_tool_xyz": "../../target/release/nonexistent_xyz"},
        }
        result = bench.find_tool("nonexistent_tool_xyz", config)
        self.assertIsNone(result)

    def test_absolute_path_still_works(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            fake_pybun = _make_fake_binary(tmp / "pybun")

            config = {
                "_base_dir": "/some/other/dir",
                "paths": {"pybun": str(fake_pybun)},
            }
            result = bench.find_tool("pybun", config)
            self.assertEqual(result, str(fake_pybun))

    def test_base_dir_stored_in_config_after_load(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            config: dict = {}
            config["_base_dir"] = str(tmp)
            self.assertEqual(config["_base_dir"], str(tmp))


if __name__ == "__main__":
    unittest.main()
