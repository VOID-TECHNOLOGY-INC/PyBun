#!/usr/bin/env python3
"""
Generate release notes and a changelog section from git tags.

Expected usage (GA release automation):
  python scripts/release/generate_release_notes.py \
      --repo . \
      --previous-tag v0.1.0 \
      --tag v0.2.0 \
      --notes-output RELEASE_NOTES.md \
      --changelog CHANGELOG.md \
      --format json
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple


COMMIT_HEADER = re.compile(r"^(?P<type>[a-zA-Z]+)(?P<bang>!)?:\s*(?P<body>.+)$")
SECTIONS = {
    "feat": "Features",
    "fix": "Fixes",
    "refactor": "Refactors",
    "perf": "Performance",
    "docs": "Docs",
    "chore": "Chores",
    "test": "Tests",
}


@dataclass
class Commit:
    kind: str
    description: str
    breaking: bool = False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate release notes from git tags.")
    parser.add_argument("--repo", default=".", type=Path, help="Path to git repository.")
    parser.add_argument(
        "--previous-tag", required=True, help="Baseline tag (exclusive lower bound)."
    )
    parser.add_argument("--tag", required=True, help="Release tag (inclusive upper bound).")
    parser.add_argument(
        "--notes-output",
        type=Path,
        help="Write rendered release notes to this path (optional).",
    )
    parser.add_argument(
        "--changelog", type=Path, help="Prepend the release notes to CHANGELOG.md."
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format for stdout.",
    )
    parser.add_argument(
        "--release-url",
        help="Optional release URL to embed in the header (e.g., GitHub release page).",
    )
    return parser.parse_args()


def run_git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout.strip()


def collect_commits(repo: Path, previous_tag: str, tag: str) -> List[Commit]:
    range_spec = f"{previous_tag}..{tag}"
    output = run_git(repo, "log", "--pretty=%s", range_spec)
    commits: List[Commit] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        commits.append(parse_commit_line(line.strip()))
    return commits


def parse_commit_line(line: str) -> Commit:
    match = COMMIT_HEADER.match(line)
    if not match:
        return Commit(kind="other", description=line, breaking=False)

    kind = match.group("type").lower()
    description = match.group("body").strip()
    breaking = bool(match.group("bang")) or "breaking change" in description.lower()
    return Commit(kind=kind, description=description, breaking=breaking)


def group_commits(commits: List[Commit]) -> Tuple[Dict[str, List[str]], List[str]]:
    grouped: Dict[str, List[str]] = {section: [] for section in set(SECTIONS.values())}
    other: List[str] = []
    breaking: List[str] = []

    for commit in commits:
        if commit.kind == "feat":
            grouped["Features"].append(commit.description)
        elif commit.kind == "fix":
            grouped["Fixes"].append(commit.description)
        elif commit.kind == "refactor":
            grouped["Refactors"].append(commit.description)
        elif commit.kind == "perf":
            grouped["Performance"].append(commit.description)
        elif commit.kind == "docs":
            grouped["Docs"].append(commit.description)
        elif commit.kind == "chore":
            grouped["Chores"].append(commit.description)
        elif commit.kind == "test":
            grouped["Tests"].append(commit.description)
        else:
            other.append(commit.description)

        if commit.breaking:
            breaking.append(commit.description)

    if other:
        grouped["Other"] = other
    return grouped, breaking


def render_section(title: str, items: List[str]) -> List[str]:
    lines: List[str] = []
    if items:
        lines.append(f"### {title}")
        lines.extend([f"- {item}" for item in items])
        lines.append("")
    return lines


def render_notes(version: str, commits: List[Commit], release_url: str | None = None) -> str:
    grouped, breaking = group_commits(commits)

    header = f"## {version}"
    if release_url:
        header = f"{header} ({release_url})"

    lines: List[str] = [header, ""]

    if breaking:
        lines.append("### Breaking Changes")
        lines.extend([f"- {item}" for item in breaking])
        lines.append("")

    for section, title in [
        ("Features", "Features"),
        ("Fixes", "Fixes"),
        ("Performance", "Performance"),
        ("Refactors", "Refactors"),
        ("Docs", "Docs"),
        ("Tests", "Tests"),
        ("Chores", "Chores"),
        ("Other", "Other"),
    ]:
        lines.extend(render_section(title, grouped.get(section, [])))

    if len(lines) > 1 and not lines[-1]:
        lines.pop()
    return "\n".join(lines) + "\n"


def write_notes(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def update_changelog(path: Path, notes: str, previous_tag: str) -> None:
    existing = path.read_text() if path.exists() else ""
    # Strip top-level header if present for easier prepending.
    body = existing
    header = "# Changelog"
    if body.startswith(header):
        body = body[len(header) :].lstrip("\n")

    sections: List[str] = []
    sections.append(notes.strip())

    if previous_tag and f"## {previous_tag}" not in body:
        sections.append(f"## {previous_tag}\n\n- Previous release")

    if body.strip():
        sections.append(body.strip())

    merged = "\n\n".join(sections)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{header}\n\n{merged}\n")


def emit_json(
    version: str,
    previous_tag: str,
    commits: List[Commit],
    notes_path: Path | None,
    changelog_path: Path | None,
) -> None:
    grouped, breaking = group_commits(commits)
    payload = {
        "version": version,
        "previous_tag": previous_tag,
        "features": grouped.get("Features", []),
        "fixes": grouped.get("Fixes", []),
        "breaking": breaking,
        "notes_output": str(notes_path) if notes_path else None,
        "changelog": str(changelog_path) if changelog_path else None,
    }
    print(json.dumps(payload, indent=2))


def main() -> int:
    args = parse_args()

    commits = collect_commits(args.repo, args.previous_tag, args.tag)
    notes = render_notes(args.tag, commits, release_url=args.release_url)

    if args.notes_output:
        write_notes(args.notes_output, notes)

    if args.changelog:
        update_changelog(args.changelog, notes, args.previous_tag)

    if args.format == "json":
        emit_json(args.tag, args.previous_tag, commits, args.notes_output, args.changelog)
    else:
        sys.stdout.write(notes)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
