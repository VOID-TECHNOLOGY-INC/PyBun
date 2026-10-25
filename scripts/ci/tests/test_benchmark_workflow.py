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

    def test_mcp_smoke_results_are_retained_independently(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/benchmark.yml").read_text())
        steps = workflow["jobs"]["ux-gate"]["steps"]
        smoke = next(step for step in steps if step.get("name", "").startswith("MCP smoke"))
        self.assertIn("-o results-mcp-smoke", smoke["run"])
        self.assertFalse(smoke.get("continue-on-error", False))
        uploads = [step for step in steps
                   if step.get("uses", "").startswith("actions/upload-artifact@")]
        upload = next(step for step in uploads
                      if step["with"]["path"] == "scripts/benchmark/results-mcp-smoke/")
        self.assertEqual(upload["if"],
                         "${{ !cancelled() && hashFiles('scripts/benchmark/results-mcp-smoke/**') != '' }}")
        self.assertEqual(upload["with"]["if-no-files-found"], "error")
        self.assertIn("${{ matrix.os }}", upload["with"]["name"])
        self.assertEqual(len({step["with"]["name"] for step in uploads}), len(uploads))


if __name__ == "__main__":
    unittest.main()
