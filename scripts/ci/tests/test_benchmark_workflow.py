"""Check benchmark failure-evidence retention policy."""

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[3]


class BenchmarkWorkflowTests(unittest.TestCase):
    def test_uv_is_pinned_to_supported_adapter_version(self):
        import shlex
        workflow = yaml.safe_load((ROOT / ".github/workflows/benchmark.yml").read_text())
        steps = workflow["jobs"]["ux-gate"]["steps"]
        install = next(step for step in steps if step.get("name") == "Install uv")
        tokens = shlex.split(install["run"])
        self.assertIn("uv==0.12.13", tokens)
        self.assertIn("uv --version", install["run"])
        adapter = (ROOT / "src/backend.rs").read_text()
        self.assertIn("supports uv >=0.12.0,<0.13.0", adapter)

    def test_results_upload_runs_after_failure_only_when_files_exist(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/benchmark.yml").read_text())
        steps = workflow["jobs"]["ux-gate"]["steps"]
        upload = next(step for step in steps if step.get("name") == "Upload results")
        gate = next(step for step in steps if step.get("name") == "UX gate")
        self.assertEqual(upload["if"],
                         "${{ !cancelled() && hashFiles('scripts/benchmark/results-ci/**') != '' }}")
        self.assertEqual(upload["with"]["if-no-files-found"], "error")
        self.assertFalse(gate.get("continue-on-error", False))
        self.assertIn("${{ matrix.os }}", upload["with"]["name"])


if __name__ == "__main__":
    unittest.main()
