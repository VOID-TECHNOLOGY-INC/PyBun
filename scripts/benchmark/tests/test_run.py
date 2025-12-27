import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scenarios import run as run_scenario


class TestRunScenario(unittest.TestCase):
    def test_resolve_pep723_script_default(self) -> None:
        base_dir = Path(__file__).resolve().parents[1]
        script = run_scenario.resolve_pep723_script(base_dir, {})
        self.assertTrue(script.exists())
        self.assertTrue(str(script).endswith("fixtures/pep723.py"))


if __name__ == "__main__":
    unittest.main()
