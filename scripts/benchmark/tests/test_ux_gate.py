import sys
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


if __name__ == "__main__":
    unittest.main()

