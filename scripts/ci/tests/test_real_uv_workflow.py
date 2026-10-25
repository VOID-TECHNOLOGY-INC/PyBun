from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[3]


class RealUvWorkflowTests(unittest.TestCase):
    def test_real_uv_tests_run_in_regular_test_and_coverage_jobs(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        for name, invocation in [("test", "cargo test"), ("coverage", "cargo llvm-cov")]:
            with self.subTest(job=name):
                steps = workflow["jobs"][name]["steps"]
                install = next(i for i, s in enumerate(steps)
                               if "uv==0.12.13" in s.get("run", ""))
                execute = next(i for i, s in enumerate(steps)
                               if invocation in s.get("run", ""))
                self.assertLess(install, execute)
                self.assertNotIn("--skip real_uv", steps[execute]["run"])
                self.assertFalse(steps[execute].get("continue-on-error", False))
        source = (ROOT / "tests/cli_uv_backend.rs").read_text()
        private = (ROOT / "tests/cli_private_index.rs").read_text()
        self.assertNotIn("PYBUN_E2E_NETWORK", source)
        self.assertNotIn("PYBUN_E2E_NETWORK", private)
        self.assertIn('#[ignore = "Requires live PyPI', source)


if __name__ == "__main__":
    unittest.main()
