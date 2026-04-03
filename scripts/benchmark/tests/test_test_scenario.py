import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scenarios import test as test_scenario


class TestCreateTestSuite(unittest.TestCase):
    def test_create_test_suite_creates_missing_parent_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)

            tests_dir = test_scenario.create_test_suite(
                root / "large",
                num_files=2,
                tests_per_file=3,
            )

            self.assertEqual(tests_dir, root / "large" / "tests")
            self.assertTrue(tests_dir.is_dir())
            self.assertEqual(len(list(tests_dir.glob("test_module_*.py"))), 2)
            self.assertTrue((tests_dir / "test_module_000.py").read_text())


if __name__ == "__main__":
    unittest.main()
