import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import bench


def load_resolution_module():
    path = Path(__file__).resolve().parents[1] / "scenarios" / "resolution.py"
    spec = importlib.util.spec_from_file_location("resolution_scenario", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class TestResolutionScenario(unittest.TestCase):
    def test_build_pybun_resolution_command_generates_pep723_script(self) -> None:
        module = load_resolution_module()

        with tempfile.TemporaryDirectory() as tmpdir:
            command = module.build_pybun_resolution_command(
                "/mock/pybun",
                Path(tmpdir),
                module.SINGLE_PACKAGE_PYPROJECT,
            )

            self.assertEqual(command[:3], ["/mock/pybun", "lock", "--script"])
            self.assertEqual(command[-1], "--format=json")
            script_path = Path(command[3])
            self.assertTrue(script_path.exists())
            self.assertIn('#   "requests>=2.28.0",', script_path.read_text())

    def test_pybun_resolution_benchmark_uses_lock_script_command(self) -> None:
        module = load_resolution_module()
        commands: list[list[str]] = []

        def fake_find_tool(name: str, config: dict) -> str | None:
            return "/mock/pybun" if name == "pybun" else None

        def fake_is_tool_enabled(name: str, config: dict) -> bool:
            return False

        def fake_measure_command(cmd: list[str], **kwargs) -> bench.BenchResult:
            commands.append(cmd)
            return bench.BenchResult(
                scenario="",
                tool="pybun",
                duration_ms=1.0,
                metadata={},
            )

        module.BenchResult = bench.BenchResult
        module.find_tool = fake_find_tool
        module.is_tool_enabled = fake_is_tool_enabled
        module.measure_command = fake_measure_command

        results = module.resolution_benchmark(
            {"general": {"iterations": 1, "warmup": 0}},
            {"fixtures": ["small"]},
            Path(__file__).resolve().parents[1],
        )

        self.assertEqual(len(commands), 4)
        for cmd in commands:
            self.assertEqual(cmd[:3], ["/mock/pybun", "lock", "--script"])
            self.assertEqual(cmd[-1], "--format=json")
            self.assertNotIn("--dry-run", cmd)
        self.assertEqual(
            [result.scenario for result in results],
            [
                "B1.1_resolution",
                "B1.4_conflict",
                "B1.5_cached_cold",
                "B1.5_cached_warm",
            ],
        )


if __name__ == "__main__":
    unittest.main()
