#!/usr/bin/env python3
"""Verify release artifacts, signatures, SBOM and provenance before publication."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tarfile
from pathlib import Path
from urllib.parse import urlparse

import generate_manifest
import generate_sbom

SHA256 = re.compile(r"[0-9a-f]{64}")


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def required_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise ValueError(f"{label} requires a lowercase SHA-256 digest")
    return value


def required_file(path: Path, label: str) -> Path:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"Missing {label}: {path}")
    return path


def find_file(root: Path, name: object, label: str) -> Path:
    if not isinstance(name, str) or not name or Path(name).name != name or name in (".", ".."):
        raise ValueError(f"Invalid {label} filename: {name}")
    matches = [path for path in root.rglob(name) if path.name == name and path.is_file() and not path.is_symlink()]
    if len(matches) != 1:
        raise ValueError(f"Expected one {label} named {name} under {root}; found {len(matches)}")
    return matches[0]


def verify_url(entry: dict, name: str, label: str) -> None:
    url = entry.get("url")
    if not isinstance(url, str) or urlparse(url).scheme != "https" or Path(urlparse(url).path).name != name:
        raise ValueError(f"{label} URL does not identify {name}")


def parse_checksums(path: Path) -> dict[str, str]:
    required_file(path, "checksums file")
    mapping = {}
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 2 or parts[1] in mapping or Path(parts[1]).name != parts[1]:
            raise ValueError(f"Invalid or duplicate checksums entry: {line}")
        mapping[parts[1]] = required_digest(parts[0], "checksums entry")
    if not mapping:
        raise ValueError("Empty checksums file")
    return mapping


def verify_attachment(path: Path, entry: object, label: str) -> None:
    required_file(path, label)
    if not isinstance(entry, dict) or entry.get("name") != path.name:
        raise ValueError(f"Manifest {label} entry does not match {path.name}")
    verify_url(entry, path.name, label)
    if digest(path) != required_digest(entry.get("sha256"), f"{label} sha256"):
        raise ValueError(f"{label} SHA-256 mismatch: {path.name}")


def verify_assets(root: Path, assets: list, checksums: dict[str, str] | None, public_key: Path) -> dict[str, str]:
    key = required_file(public_key, "public key").read_text().strip()
    if not key:
        raise ValueError("Empty public key")
    subjects = {}
    for asset in assets:
        if not isinstance(asset, dict):
            raise TypeError("Manifest asset must be an object")
        name = asset.get("name")
        archive = find_file(root, name, "artifact")
        if name in subjects:
            raise ValueError(f"Duplicate manifest asset: {name}")
        expected = required_digest(asset.get("sha256"), f"asset {name} sha256")
        verify_url(asset, name, "artifact")
        if digest(archive) != expected:
            raise ValueError(f"Artifact SHA-256 mismatch: {name}")
        if checksums is not None and checksums.get(name) != expected:
            raise ValueError(f"Checksums missing or mismatched for {name}")
        target = asset.get("target")
        if not isinstance(target, str) or not target:
            raise ValueError(f"Missing release target for {name}")
        if target.endswith("-unknown-linux-gnu"):
            actual = generate_manifest.glibc_requirement(archive, target)
            if asset.get("compat") != {"libc": "glibc", "min_glibc": actual}:
                raise ValueError(f"GLIBC compatibility mismatch for {name}: ELF requires {actual}")
        signature = asset.get("signature")
        if not isinstance(signature, dict) or signature.get("type") != "minisign":
            raise ValueError(f"Missing minisign signature for {name}")
        signature_file = find_file(root, f"{name}.minisig", "signature")
        verify_url(signature, signature_file.name, "signature")
        value = signature_file.read_text().strip()
        if not value or signature.get("value") != value or signature.get("public_key") != key:
            raise ValueError(f"Signature evidence differs from the supplied public key or signature for {name}")
        result = subprocess.run(["minisign", "-Vm", str(archive), "-x", str(signature_file), "-p", str(public_key)], check=False, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            raise ValueError(f"Invalid minisign signature for {name}")
        subjects[name] = expected
    if checksums is not None and set(checksums) != set(subjects):
        raise ValueError("Checksums entries do not match manifest assets")
    return subjects


def verify_provenance(path: Path, subjects: dict[str, str]) -> None:
    statement = json.loads(path.read_text())
    if not isinstance(statement, dict) or statement.get("_type") != "https://in-toto.io/Statement/v1" or statement.get("predicateType") != "https://slsa.dev/provenance/v1":
        raise ValueError("Invalid provenance statement")
    listed = statement.get("subject")
    if not isinstance(listed, list) or len(listed) != len(subjects):
        raise ValueError("Provenance subjects do not match manifest assets")
    actual = {}
    for item in listed:
        if not isinstance(item, dict) or not isinstance(item.get("digest"), dict):
            raise TypeError("Invalid provenance subject")
        name = item.get("name")
        if not isinstance(name, str) or name in actual:
            raise ValueError("Invalid or duplicate provenance subject")
        actual[name] = required_digest(item["digest"].get("sha256"), f"provenance subject {name}")
    if actual != subjects:
        raise ValueError("Provenance subjects do not match artifact names and digests")


def verify_sbom(path: Path, version: str, assets: list[dict]) -> None:
    document = json.loads(path.read_text())
    root, components = generate_sbom.validate_bom(document)
    if root.get("version") != version:
        raise ValueError("SBOM version differs from release manifest")
    targets = [item for item in components if item.get("type") == "application" and item.get("name") == "pybun"]
    if len(targets) != len(assets):
        raise ValueError("SBOM target inventory differs from release assets")
    expected = {asset["name"]: (asset["target"], asset["sha256"]) for asset in assets}
    actual = {}
    for component in targets:
        name = generate_sbom.property_value(component, "pybun:archive")
        target = generate_sbom.property_value(component, "pybun:release_target")
        lock = generate_sbom.property_value(component, "pybun:cargo_lock_sha256")
        if name in actual or not isinstance(lock, str) or not SHA256.fullmatch(lock):
            raise ValueError("SBOM target lacks unique archive or Cargo.lock evidence")
        hashes = component.get("hashes")
        artifact_hash = hashes[0].get("content") if isinstance(hashes, list) and hashes else None
        actual[name] = (target, artifact_hash)
    if actual != expected:
        raise ValueError("SBOM target archives or hashes differ from manifest assets")
    graph = {item["ref"]: set(item["dependsOn"]) for item in document["dependencies"]}
    reachable = {root["bom-ref"]}
    queue = [root["bom-ref"]]
    for reference in queue:
        for dependency in graph[reference]:
            if dependency not in reachable:
                reachable.add(dependency)
                queue.append(dependency)
    if reachable != set(graph):
        raise ValueError("SBOM has disconnected or missing dependencies")
    for component in targets:
        direct = graph[component["bom-ref"]]
        if not direct or not any(graph[reference] for reference in direct):
            raise ValueError("SBOM target lacks direct and transitive dependencies")


def verify(args: argparse.Namespace) -> int:
    if not args.artifacts_dir.is_dir() or args.artifacts_dir.is_symlink():
        raise ValueError(f"Missing artifacts directory: {args.artifacts_dir}")
    manifest = json.loads(required_file(args.manifest, "manifest").read_text())
    if not isinstance(manifest, dict) or not isinstance(manifest.get("version"), str) or not manifest["version"]:
        raise ValueError("Manifest has no release version")
    assets = manifest.get("assets")
    if not isinstance(assets, list) or not assets:
        raise ValueError("Manifest assets must be a nonempty list")
    if args.public_key is None:
        raise ValueError("A public key is required to verify signatures")
    checksums = parse_checksums(args.checksums) if args.checksums is not None else None
    verify_attachment(args.sbom, manifest.get("sbom"), "SBOM")
    verify_attachment(args.provenance, manifest.get("provenance"), "provenance")
    subjects = verify_assets(args.artifacts_dir, assets, checksums, args.public_key)
    archives = [path for path in args.artifacts_dir.rglob("*") if path.name.endswith((".tar.gz", ".zip"))]
    if any(not path.is_file() or path.is_symlink() for path in archives) or len({path.name for path in archives}) != len(archives) or {path.name for path in archives} != set(subjects):
        raise ValueError("Unlisted, unsigned or duplicate release archives under artifacts directory")
    verify_provenance(args.provenance, subjects)
    verify_sbom(args.sbom, manifest["version"], assets)
    print(f"Security artifacts verified: assets={len(subjects)}, sbom={args.sbom.name}, provenance={args.provenance.name}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-dir", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--sbom", required=True, type=Path)
    parser.add_argument("--provenance", required=True, type=Path)
    parser.add_argument("--checksums", type=Path)
    parser.add_argument("--public-key", type=Path)
    args = parser.parse_args()
    try:
        return verify(args)
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError, tarfile.TarError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
