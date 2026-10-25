from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[3]


class LinuxCompatibilityWorkflowTests(unittest.TestCase):
    def test_pr_ci_smokes_both_native_gnu_targets(self):
        ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        job = ci["jobs"]["linux-compatibility"]
        entries = job["strategy"]["matrix"]["include"]
        self.assertEqual({(x["os"], x["target"]) for x in entries}, {
            ("ubuntu-22.04", "x86_64-unknown-linux-gnu"),
            ("ubuntu-22.04-arm", "aarch64-unknown-linux-gnu"),
        })
        commands = "\n".join(step.get("run", "") for step in job["steps"])
        self.assertIn("cargo build --locked --release --target", commands)
        self.assertIn("smoke_linux_compat.py", commands)
        self.assertFalse(any(s.get("continue-on-error", False) for s in job["steps"]))

    def test_release_smokes_the_packaged_gnu_binary_before_upload(self):
        release = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
        job = release["jobs"]["build"]
        arm = next(e for e in job["strategy"]["matrix"]["include"]
                   if e["target"] == "aarch64-unknown-linux-gnu")
        self.assertEqual(arm["os"], "ubuntu-22.04-arm")
        steps = job["steps"]
        smoke = next(i for i, s in enumerate(steps) if "smoke_linux_compat.py" in s.get("run", ""))
        upload = next(i for i, s in enumerate(steps) if s.get("name") == "Upload artifact")
        self.assertLess(smoke, upload)
        self.assertIn("unknown-linux-gnu", steps[smoke]["if"])
        self.assertIn(".tar.gz", steps[smoke]["run"])


if __name__ == "__main__":
    unittest.main()
