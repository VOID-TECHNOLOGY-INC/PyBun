#!/usr/bin/env python3
"""
UX gate for PyBun benchmarks.

This script evaluates a benchmark JSON report against a small set of "perceived performance"
criteria and exits non-zero when any rule fails.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Try to import tomllib (Python 3.11+) or fall back to toml
try:
    import tomllib
except ImportError:
    try:
        import toml as tomllib  # type: ignore
    except ImportError:
        print("Error: Please install toml package: pip install toml", file=sys.stderr)
        raise


@dataclass
class UxGateOutcome:
    passed: bool
    failures: list[dict[str, Any]] = field(default_factory=list)


def _index_results(report: dict) -> dict[tuple[str, str], dict]:
    indexed: dict[tuple[str, str], dict] = {}
    for item in report.get("results", []) or []:
        scenario = item.get("scenario")
        tool = item.get("tool")
        if isinstance(scenario, str) and isinstance(tool, str):
            indexed[(scenario, tool)] = item
    return indexed


def evaluate_rules(report: dict, rules: list[dict]) -> UxGateOutcome:
    indexed = _index_results(report)
    failures: list[dict[str, Any]] = []

    for rule in rules:
        scenario = rule.get("scenario")
        tool = rule.get("tool")
        if not isinstance(scenario, str) or not isinstance(tool, str):
            failures.append({"rule": rule, "reason": "invalid_rule"})
            continue

        result = indexed.get((scenario, tool))
        if not result:
            failures.append(
                {"scenario": scenario, "tool": tool, "reason": "missing_result"}
            )
            continue

        if result.get("success") is False:
            failures.append(
                {"scenario": scenario, "tool": tool, "reason": "unsuccessful_run"}
            )
            continue

        duration_ms = float(result.get("duration_ms", 0.0) or 0.0)

        max_ms = rule.get("max_ms")
        if max_ms is not None:
            max_ms_f = float(max_ms)
            if duration_ms > max_ms_f:
                failures.append(
                    {
                        "scenario": scenario,
                        "tool": tool,
                        "reason": "max_ms_exceeded",
                        "duration_ms": duration_ms,
                        "max_ms": max_ms_f,
                    }
                )
                continue

        compare_to = rule.get("compare_to")
        max_ratio = rule.get("max_ratio")
        if isinstance(compare_to, str) and max_ratio is not None:
            baseline = indexed.get((scenario, compare_to))
            if not baseline or baseline.get("success") is False:
                failures.append(
                    {
                        "scenario": scenario,
                        "tool": tool,
                        "reason": "missing_baseline",
                        "compare_to": compare_to,
                    }
                )
                continue

            baseline_ms = float(baseline.get("duration_ms", 0.0) or 0.0)
            if baseline_ms <= 0:
                failures.append(
                    {
                        "scenario": scenario,
                        "tool": tool,
                        "reason": "invalid_baseline_duration",
                        "compare_to": compare_to,
                        "baseline_ms": baseline_ms,
                    }
                )
                continue

            ratio = duration_ms / baseline_ms
            max_ratio_f = float(max_ratio)
            if ratio > max_ratio_f:
                failures.append(
                    {
                        "scenario": scenario,
                        "tool": tool,
                        "reason": "max_ratio_exceeded",
                        "duration_ms": duration_ms,
                        "compare_to": compare_to,
                        "baseline_ms": baseline_ms,
                        "ratio": round(ratio, 3),
                        "max_ratio": max_ratio_f,
                    }
                )

    return UxGateOutcome(passed=(len(failures) == 0), failures=failures)


def _load_report(path: Path) -> dict:
    if path.is_dir():
        candidates = sorted(path.glob("benchmark_*.json"))
        if not candidates:
            raise FileNotFoundError(f"No benchmark_*.json found in {path}")
        path = candidates[-1]

    with path.open() as f:
        return json.load(f)


def _load_rules(path: Path) -> list[dict]:
    with path.open("rb") as f:
        data = tomllib.load(f)
    rules = data.get("rules", [])
    if not isinstance(rules, list):
        raise ValueError("ux criteria must define [[rules]] as a list")
    return rules


def main() -> int:
    parser = argparse.ArgumentParser(description="PyBun UX performance gate")
    parser.add_argument(
        "results",
        help="Path to a benchmark JSON file or directory containing benchmark_*.json",
    )
    parser.add_argument(
        "--criteria",
        default=str(Path(__file__).with_name("ux_criteria.toml")),
        help="Path to UX criteria TOML (default: ux_criteria.toml)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format for gate result",
    )
    args = parser.parse_args()

    report = _load_report(Path(args.results))
    rules = _load_rules(Path(args.criteria))
    outcome = evaluate_rules(report, rules)

    if args.format == "json":
        print(json.dumps({"passed": outcome.passed, "failures": outcome.failures}, indent=2))
    else:
        if outcome.passed:
            print("UX gate: PASS")
        else:
            print(f"UX gate: FAIL ({len(outcome.failures)} failure(s))")
            for failure in outcome.failures:
                scenario = failure.get("scenario", "?")
                tool = failure.get("tool", "?")
                reason = failure.get("reason", "?")
                print(f"- {scenario} [{tool}]: {reason}")

    return 0 if outcome.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

