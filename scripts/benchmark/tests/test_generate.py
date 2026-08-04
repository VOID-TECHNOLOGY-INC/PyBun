import importlib.util
import sys
import unittest
from pathlib import Path

_GENERATE_PATH = Path(__file__).resolve().parents[1] / "report" / "generate.py"
_spec = importlib.util.spec_from_file_location("report_generate", _GENERATE_PATH)
generate = importlib.util.module_from_spec(_spec)
sys.modules["report_generate"] = generate
_spec.loader.exec_module(generate)


class TestGenerateHtmlReportEscaping(unittest.TestCase):
    def _results_with(self, scenario: str, tool: str) -> list[dict]:
        return [
            {
                "meta": {"timestamp": "now", "pybun_version": "0.0.0", "system": {}},
                "summary": {},
                "results": [
                    {
                        "scenario": scenario,
                        "tool": tool,
                        "duration_ms": 1.0,
                        "min_ms": 1.0,
                        "max_ms": 1.0,
                        "stddev_ms": 0.0,
                        "success": True,
                    }
                ],
            }
        ]

    def test_scenario_name_is_html_escaped(self) -> None:
        payload = "<script>alert('xss')</script>"
        html_out = generate.generate_html_report(self._results_with(payload, "pip"))
        self.assertNotIn(payload, html_out)
        self.assertIn("&lt;script&gt;", html_out)

    def test_tool_name_is_html_escaped(self) -> None:
        payload = "<img src=x onerror=alert(1)>"
        html_out = generate.generate_html_report(self._results_with("install", payload))
        self.assertNotIn(payload, html_out)
        self.assertIn("&lt;img", html_out)

    def test_title_is_html_escaped(self) -> None:
        payload = "<script>alert('xss')</script>"
        html_out = generate.generate_html_report(
            self._results_with("install", "pip"), title=payload
        )
        self.assertNotIn(payload, html_out)
        self.assertIn("&lt;script&gt;", html_out)

    def test_meta_and_system_fields_are_html_escaped(self) -> None:
        payload = "<script>alert('xss')</script>"
        results = [
            {
                "meta": {
                    "timestamp": payload,
                    "pybun_version": payload,
                    "system": {
                        "os": payload,
                        "os_version": payload,
                        "architecture": payload,
                        "cpu": payload,
                        "memory_gb": payload,
                        "python_version": payload,
                    },
                },
                "summary": {},
                "results": [
                    {
                        "scenario": "install",
                        "tool": "pip",
                        "duration_ms": 1.0,
                        "min_ms": 1.0,
                        "max_ms": 1.0,
                        "stddev_ms": 0.0,
                        "success": True,
                    }
                ],
            }
        ]
        html_out = generate.generate_html_report(results)
        self.assertNotIn(payload, html_out)
        self.assertIn("&lt;script&gt;", html_out)


if __name__ == "__main__":
    unittest.main()
