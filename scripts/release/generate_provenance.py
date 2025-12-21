#!/usr/bin/env python3
import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path


def sha256sum(path: Path) -> str:
    import hashlib

    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def parse_sha256sums(path: Path):
    subjects = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        digest = parts[0]
        name = parts[-1]
        subjects.append({"name": name, "digest": {"sha256": digest}})
    return subjects


def collect_subjects_from_assets(assets_dir: Path):
    subjects = []
    for path in assets_dir.rglob("*"):
        if not path.is_file():
            continue
        if not (path.name.endswith(".tar.gz") or path.name.endswith(".zip")):
            continue
        digest = sha256sum(path)
        subjects.append({"name": path.name, "digest": {"sha256": digest}})
    return subjects


def prune_none(value):
    if isinstance(value, dict):
        return {k: prune_none(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [prune_none(v) for v in value if v is not None]
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a minimal SLSA provenance statement.")
    parser.add_argument("--sha256sums", type=Path)
    parser.add_argument("--assets-dir", type=Path)
    parser.add_argument("--output", default="pybun-provenance.json", type=Path)
    parser.add_argument("--timestamp")
    parser.add_argument("--build-type")
    args = parser.parse_args()

    if args.sha256sums:
        subjects = parse_sha256sums(args.sha256sums)
    elif args.assets_dir:
        subjects = collect_subjects_from_assets(args.assets_dir)
    else:
        raise SystemExit("Provide --sha256sums or --assets-dir to derive subjects")
    if not subjects:
        raise SystemExit("SHA256SUMS did not contain any subjects")

    timestamp = args.timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo = os.environ.get("GITHUB_REPOSITORY", "pybun/pybun")
    workflow = os.environ.get("GITHUB_WORKFLOW", "Release Build")
    run_id = os.environ.get("GITHUB_RUN_ID")
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT")
    sha = os.environ.get("GITHUB_SHA")
    ref = os.environ.get("GITHUB_REF")

    build_type = args.build_type or f"{server}/{repo}/.github/workflows/release.yml"
    invocation_id = f"{server}/{repo}/actions/runs/{run_id}" if run_id else None
    builder_id = f"{server}/{repo}/.github/workflows/release.yml"

    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": build_type,
                "externalParameters": {
                    "workflow": workflow,
                    "ref": ref,
                    "sha": sha,
                },
                "internalParameters": {},
                "resolvedDependencies": [
                    {
                        "uri": f"git+{server}/{repo}@{sha}",
                        "digest": {"sha1": sha},
                    }
                ]
                if sha
                else [],
            },
            "runDetails": {
                "builder": {"id": builder_id},
                "metadata": {
                    "invocationId": invocation_id,
                    "startedOn": timestamp,
                    "finishedOn": timestamp,
                    "runAttempt": run_attempt,
                },
            },
        },
    }

    args.output.write_text(json.dumps(prune_none(statement), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
