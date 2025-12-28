import subprocess
import tempfile
import textwrap
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def write_file(repo: Path, name: str, content: str) -> None:
    path = repo / name
    path.write_text(content)
    subprocess.run(["git", "-C", str(repo), "add", name], check=True, capture_output=True)


class ReleaseNotesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(tempfile.mkdtemp())
        git(self.repo, "init")
        git(self.repo, "config", "user.name", "PyBun Tests")
        git(self.repo, "config", "user.email", "ci@example.com")
        write_file(self.repo, "README.md", "# Test repo\n")
        git(self.repo, "commit", "-m", "chore: initial")
        git(self.repo, "tag", "v0.1.0")

        write_file(self.repo, "feature.txt", "feature")
        git(self.repo, "commit", "-m", "feat: add new runner")

        write_file(self.repo, "fix.txt", "fix")
        git(self.repo, "commit", "-m", "fix: handle error path")
        git(self.repo, "tag", "v0.2.0")

    def test_generate_release_notes_cli(self):
        script = ROOT / "generate_release_notes.py"
        notes_path = self.repo / "RELEASE_NOTES.md"
        changelog_path = self.repo / "CHANGELOG.md"

        result = subprocess.run(
            [
                sys.executable,
                str(script),
                "--repo",
                str(self.repo),
                "--previous-tag",
                "v0.1.0",
                "--tag",
                "v0.2.0",
                "--notes-output",
                str(notes_path),
                "--changelog",
                str(changelog_path),
            ],
            capture_output=True,
            text=True,
        )

        self.assertEqual(
            result.returncode,
            0,
            f"release notes generator failed: {result.stderr}",
        )
        notes = notes_path.read_text()
        self.assertIn("## v0.2.0", notes)
        self.assertIn("- add new runner", notes)
        self.assertIn("- handle error path", notes)

        changelog = changelog_path.read_text()
        self.assertIn("## v0.2.0", changelog)
        self.assertIn("## v0.1.0", changelog)
        self.assertIn("Features", changelog)
        self.assertIn("Fixes", changelog)

    def test_json_format_summary(self):
        script = ROOT / "generate_release_notes.py"
        output_path = self.repo / "NOTES.md"

        result = subprocess.run(
            [
                sys.executable,
                str(script),
                "--repo",
                str(self.repo),
                "--previous-tag",
                "v0.1.0",
                "--tag",
                "v0.2.0",
                "--notes-output",
                str(output_path),
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
        )

        self.assertEqual(
            result.returncode, 0, f"json format should succeed: {result.stderr}"
        )
        self.assertTrue(
            result.stdout.strip().startswith("{"),
            "json output should start with object",
        )
        data = result.stdout.strip()
        self.assertIn('"version": "v0.2.0"', data)
        self.assertIn('"features":', data)
        self.assertIn('"fixes":', data)


if __name__ == "__main__":
    unittest.main()
