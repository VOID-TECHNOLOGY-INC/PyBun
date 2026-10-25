from __future__ import annotations

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]


class ReleaseVerifierWorkflowTests(unittest.TestCase):
    def test_python_test_runners_install_minisign_and_verify_before_attestation(self):
        ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        python_steps = ci["jobs"]["python-tests"]["steps"]
        self.assertTrue(any("minisign" in step.get("name", "").lower() for step in python_steps))
        release = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
        names = [step.get("name") for step in release["jobs"]["metadata"]["steps"]]
        self.assertLess(names.index("Verify security artifacts"), names.index("Attest SBOM"))
        self.assertLess(names.index("Verify security artifacts"), names.index("Upload release metadata"))


if __name__ == "__main__":
    unittest.main()
