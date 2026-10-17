import sys
import subprocess
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ux_gate


class TestUxGate(unittest.TestCase):
    def test_rule_fails_when_ratio_exceeds_threshold(self) -> None:
        report = {
            "results": [
                {
                    "scenario": "B3.1_simple_startup",
                    "tool": "pybun",
                    "duration_ms": 30.0,
                    "success": True,
                },
                {
                    "scenario": "B3.1_simple_startup",
                    "tool": "python",
                    "duration_ms": 20.0,
                    "success": True,
                },
            ]
        }
        rules = [
            {
                "scenario": "B3.1_simple_startup",
                "tool": "pybun",
                "compare_to": "python",
                "max_ratio": 1.25,
            }
        ]

        outcome = ux_gate.evaluate_rules(report, rules)
        self.assertFalse(outcome.passed)
        self.assertEqual(len(outcome.failures), 1)


    def test_cli_failure_includes_measured_values_and_threshold(self):
        fixture = Path(__file__).parent / "fixtures/benchmark_gate_failure.json"
        with tempfile.TemporaryDirectory() as directory:
            criteria = Path(directory) / "criteria.toml"
            criteria.write_text(
                '[[rules]]\nscenario="B3.1_simple_startup"\ntool="pybun"\n'
                'compare_to="python"\nmax_ratio=1.5\n'
            )
            result = subprocess.run([
                sys.executable, str(Path(ux_gate.__file__)), str(fixture),
                "--criteria", str(criteria), "--format", "text"
            ], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        for detail in ["duration_ms=50.0", "baseline_ms=10.0", "ratio=5.0", "max_ratio=1.5"]:
            self.assertIn(detail, result.stdout)


if __name__ == "__main__":
    unittest.main()

