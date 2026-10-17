"""Regression checks for Python test entry points in hosted workflows."""

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[3]
SHIM = "python -m unittest discover -s pybun/tests -v"
RELEASE = "python -m unittest discover -s scripts/release/tests -v"
BENCHMARK = "python -m pytest scripts/benchmark/tests -q"


class PythonWorkflowTests(unittest.TestCase):
    def test_pr_ci_runs_all_python_suites(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        job = workflow["jobs"]["python-tests"]
        self.assertEqual(job["strategy"]["matrix"]["os"],
                         ["ubuntu-latest", "macos-latest"])
        steps = job["steps"]
        self.assertTrue(any(step.get("with", {}).get("python-version") == "3.11"
                            for step in steps))
        commands = [step.get("run", "") for step in steps]
        for command in (SHIM, RELEASE, BENCHMARK):
            self.assertIn(command, commands)
        self.assertFalse(any(step.get("continue-on-error", False) for step in steps))

    def test_publish_tests_shim_before_building(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/publish-pypi.yml").read_text())
        commands = [step.get("run", "") for step in workflow["jobs"]["publish"]["steps"]]
        self.assertLess(commands.index(SHIM), commands.index("python -m build"))


if __name__ == "__main__":
    unittest.main()
