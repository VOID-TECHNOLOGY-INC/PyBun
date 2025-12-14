#!/usr/bin/env python3
"""
Benchmark Report Generator

Generates reports from benchmark results in various formats.

Usage:
    python generate.py results/benchmark_*.json -o report.md
    python generate.py results/ --format html -o report.html
    python generate.py results/ --compare baseline.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


def load_results(path: Path) -> list[dict]:
    """Load benchmark results from file or directory."""
    results = []
    
    if path.is_file():
        with open(path) as f:
            data = json.load(f)
            results.append(data)
    elif path.is_dir():
        for json_file in sorted(path.glob("benchmark_*.json")):
            with open(json_file) as f:
                data = json.load(f)
                data["_source_file"] = json_file.name
                results.append(data)
    
    return results


def calculate_comparison(current: dict, baseline: dict) -> dict:
    """Calculate comparison metrics between current and baseline results."""
    comparison = {
        "improvements": [],
        "regressions": [],
        "unchanged": [],
    }
    
    current_by_key = {
        (r["scenario"], r["tool"]): r
        for r in current.get("results", [])
    }
    
    baseline_by_key = {
        (r["scenario"], r["tool"]): r
        for r in baseline.get("results", [])
    }
    
    for key, curr in current_by_key.items():
        if key not in baseline_by_key:
            continue
        
        base = baseline_by_key[key]
        curr_ms = curr.get("duration_ms", 0)
        base_ms = base.get("duration_ms", 0)
        
        if base_ms == 0:
            continue
        
        change_pct = ((curr_ms - base_ms) / base_ms) * 100
        
        item = {
            "scenario": key[0],
            "tool": key[1],
            "current_ms": curr_ms,
            "baseline_ms": base_ms,
            "change_pct": round(change_pct, 1),
        }
        
        if change_pct < -5:  # 5% faster
            comparison["improvements"].append(item)
        elif change_pct > 10:  # 10% slower (regression threshold)
            comparison["regressions"].append(item)
        else:
            comparison["unchanged"].append(item)
    
    return comparison


def generate_markdown_report(
    results: list[dict],
    baseline: dict | None = None,
    title: str = "PyBun Benchmark Report",
) -> str:
    """Generate a Markdown report from benchmark results."""
    lines = [
        f"# {title}",
        "",
    ]
    
    if not results:
        lines.append("No benchmark results found.")
        return "\n".join(lines)
    
    # Use the most recent result
    latest = results[-1]
    meta = latest.get("meta", {})
    
    # Header
    lines.extend([
        f"**Generated:** {meta.get('timestamp', 'Unknown')}",
        f"**PyBun Version:** {meta.get('pybun_version', 'Unknown')}",
        "",
    ])
    
    # System info
    sys_info = meta.get("system", {})
    if sys_info:
        lines.extend([
            "## System Information",
            "",
            f"| Property | Value |",
            f"|----------|-------|",
            f"| OS | {sys_info.get('os', 'Unknown')} {sys_info.get('os_version', '')} |",
            f"| Architecture | {sys_info.get('architecture', 'Unknown')} |",
            f"| CPU | {sys_info.get('cpu', 'Unknown')} |",
            f"| CPU Cores | {sys_info.get('cpu_count', 'Unknown')} |",
            f"| Memory | {sys_info.get('memory_gb', 'Unknown')} GB |",
            f"| Python | {sys_info.get('python_version', 'Unknown')} |",
            "",
        ])
    
    # Summary
    summary = latest.get("summary", {})
    lines.extend([
        "## Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total Scenarios | {summary.get('total_scenarios', 0)} |",
        f"| Total Benchmarks | {summary.get('total_benchmarks', 0)} |",
        f"| Successful | {summary.get('successful', 0)} |",
        f"| Failed | {summary.get('failed', 0)} |",
        f"| PyBun Wins | {summary.get('pybun_wins', 0)} |",
        f"| PyBun Losses | {summary.get('pybun_losses', 0)} |",
        f"| Average Speedup | {summary.get('average_speedup', 1.0):.2f}x |",
        "",
    ])
    
    # Comparison with baseline
    if baseline:
        comparison = calculate_comparison(latest, baseline)
        
        lines.extend([
            "## Comparison with Baseline",
            "",
        ])
        
        if comparison["regressions"]:
            lines.extend([
                "### ⚠️ Regressions (>10% slower)",
                "",
                "| Scenario | Tool | Current | Baseline | Change |",
                "|----------|------|---------|----------|--------|",
            ])
            for item in sorted(comparison["regressions"], key=lambda x: x["change_pct"], reverse=True):
                lines.append(
                    f"| {item['scenario']} | {item['tool']} | {item['current_ms']:.2f}ms | {item['baseline_ms']:.2f}ms | +{item['change_pct']:.1f}% |"
                )
            lines.append("")
        
        if comparison["improvements"]:
            lines.extend([
                "### ✅ Improvements (>5% faster)",
                "",
                "| Scenario | Tool | Current | Baseline | Change |",
                "|----------|------|---------|----------|--------|",
            ])
            for item in sorted(comparison["improvements"], key=lambda x: x["change_pct"]):
                lines.append(
                    f"| {item['scenario']} | {item['tool']} | {item['current_ms']:.2f}ms | {item['baseline_ms']:.2f}ms | {item['change_pct']:.1f}% |"
                )
            lines.append("")
    
    # Detailed results by scenario
    bench_results = latest.get("results", [])
    by_scenario: dict[str, list[dict]] = {}
    for r in bench_results:
        by_scenario.setdefault(r["scenario"], []).append(r)
    
    lines.extend([
        "## Detailed Results",
        "",
    ])
    
    for scenario in sorted(by_scenario.keys()):
        scenario_results = by_scenario[scenario]
        
        lines.extend([
            f"### {scenario}",
            "",
            "| Tool | Duration (ms) | Min | Max | StdDev | Status |",
            "|------|--------------|-----|-----|--------|--------|",
        ])
        
        for r in sorted(scenario_results, key=lambda x: x.get("duration_ms", 0)):
            status = "✅" if r.get("success", True) else "❌"
            error = f" ({r.get('error', '')[:30]}...)" if r.get("error") else ""
            lines.append(
                f"| {r['tool']} | {r.get('duration_ms', 0):.2f} | {r.get('min_ms', 0):.2f} | {r.get('max_ms', 0):.2f} | {r.get('stddev_ms', 0):.2f} | {status}{error} |"
            )
        
        lines.append("")
    
    # Footer
    lines.extend([
        "---",
        "",
        f"*Report generated at {datetime.now().isoformat()}*",
    ])
    
    return "\n".join(lines)


def generate_html_report(
    results: list[dict],
    baseline: dict | None = None,
    title: str = "PyBun Benchmark Report",
) -> str:
    """Generate an HTML report from benchmark results."""
    latest = results[-1] if results else {}
    meta = latest.get("meta", {})
    summary = latest.get("summary", {})
    sys_info = meta.get("system", {})
    
    html = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        :root {{
            --bg: #0d1117;
            --fg: #c9d1d9;
            --accent: #58a6ff;
            --success: #3fb950;
            --warning: #d29922;
            --error: #f85149;
            --border: #30363d;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--fg);
            margin: 0;
            padding: 2rem;
            line-height: 1.6;
        }}
        h1, h2, h3 {{
            color: var(--accent);
            border-bottom: 1px solid var(--border);
            padding-bottom: 0.5rem;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 1rem 0;
        }}
        th, td {{
            border: 1px solid var(--border);
            padding: 0.5rem 1rem;
            text-align: left;
        }}
        th {{
            background: #161b22;
        }}
        tr:nth-child(even) {{
            background: #161b22;
        }}
        .success {{ color: var(--success); }}
        .warning {{ color: var(--warning); }}
        .error {{ color: var(--error); }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 1rem 0;
        }}
        .summary-card {{
            background: #161b22;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
        }}
        .summary-card h3 {{
            margin: 0;
            border: none;
            font-size: 0.9rem;
            color: var(--fg);
        }}
        .summary-card .value {{
            font-size: 2rem;
            font-weight: bold;
            color: var(--accent);
        }}
        .bar {{
            background: var(--border);
            height: 20px;
            border-radius: 4px;
            overflow: hidden;
        }}
        .bar-fill {{
            height: 100%;
            background: var(--accent);
        }}
    </style>
</head>
<body>
    <h1>{title}</h1>
    
    <p>
        <strong>Generated:</strong> {meta.get('timestamp', 'Unknown')}<br>
        <strong>PyBun Version:</strong> {meta.get('pybun_version', 'Unknown')}
    </p>
    
    <h2>System Information</h2>
    <table>
        <tr><th>Property</th><th>Value</th></tr>
        <tr><td>OS</td><td>{sys_info.get('os', 'Unknown')} {sys_info.get('os_version', '')}</td></tr>
        <tr><td>Architecture</td><td>{sys_info.get('architecture', 'Unknown')}</td></tr>
        <tr><td>CPU</td><td>{sys_info.get('cpu', 'Unknown')}</td></tr>
        <tr><td>Memory</td><td>{sys_info.get('memory_gb', 'Unknown')} GB</td></tr>
        <tr><td>Python</td><td>{sys_info.get('python_version', 'Unknown')}</td></tr>
    </table>
    
    <h2>Summary</h2>
    <div class="summary-grid">
        <div class="summary-card">
            <h3>Total Benchmarks</h3>
            <div class="value">{summary.get('total_benchmarks', 0)}</div>
        </div>
        <div class="summary-card">
            <h3>Successful</h3>
            <div class="value success">{summary.get('successful', 0)}</div>
        </div>
        <div class="summary-card">
            <h3>Failed</h3>
            <div class="value error">{summary.get('failed', 0)}</div>
        </div>
        <div class="summary-card">
            <h3>PyBun Wins</h3>
            <div class="value">{summary.get('pybun_wins', 0)}</div>
        </div>
        <div class="summary-card">
            <h3>Average Speedup</h3>
            <div class="value">{summary.get('average_speedup', 1.0):.2f}x</div>
        </div>
    </div>
    
    <h2>Detailed Results</h2>
"""
    
    # Group by scenario
    bench_results = latest.get("results", [])
    by_scenario: dict[str, list[dict]] = {}
    for r in bench_results:
        by_scenario.setdefault(r["scenario"], []).append(r)
    
    for scenario in sorted(by_scenario.keys()):
        scenario_results = by_scenario[scenario]
        
        html += f"""
    <h3>{scenario}</h3>
    <table>
        <tr>
            <th>Tool</th>
            <th>Duration (ms)</th>
            <th>Min</th>
            <th>Max</th>
            <th>StdDev</th>
            <th>Status</th>
        </tr>
"""
        
        for r in sorted(scenario_results, key=lambda x: x.get("duration_ms", 0)):
            status_class = "success" if r.get("success", True) else "error"
            status_icon = "✅" if r.get("success", True) else "❌"
            
            html += f"""
        <tr>
            <td>{r['tool']}</td>
            <td>{r.get('duration_ms', 0):.2f}</td>
            <td>{r.get('min_ms', 0):.2f}</td>
            <td>{r.get('max_ms', 0):.2f}</td>
            <td>{r.get('stddev_ms', 0):.2f}</td>
            <td class="{status_class}">{status_icon}</td>
        </tr>
"""
        
        html += "    </table>\n"
    
    html += f"""
    <hr>
    <p><em>Report generated at {datetime.now().isoformat()}</em></p>
</body>
</html>
"""
    
    return html


def main():
    parser = argparse.ArgumentParser(
        description="Generate benchmark reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "input",
        type=Path,
        help="Input file or directory containing benchmark results",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Output file path",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "html", "json"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    parser.add_argument(
        "--compare",
        type=Path,
        help="Baseline results file for comparison",
    )
    parser.add_argument(
        "--title",
        default="PyBun Benchmark Report",
        help="Report title",
    )
    
    args = parser.parse_args()
    
    # Load results
    results = load_results(args.input)
    if not results:
        print(f"No results found in {args.input}", file=sys.stderr)
        return 1
    
    # Load baseline if specified
    baseline = None
    if args.compare and args.compare.exists():
        with open(args.compare) as f:
            baseline = json.load(f)
    
    # Generate report
    if args.format == "markdown":
        report = generate_markdown_report(results, baseline, args.title)
        ext = ".md"
    elif args.format == "html":
        report = generate_html_report(results, baseline, args.title)
        ext = ".html"
    else:
        report = json.dumps(results[-1], indent=2)
        ext = ".json"
    
    # Output
    if args.output:
        output_path = args.output
        if output_path.suffix == "":
            output_path = output_path.with_suffix(ext)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report)
        print(f"Report saved to {output_path}")
    else:
        print(report)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

