#!/usr/bin/env python3
"""Describe the crates compiled into each released PyBun target."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import tomllib


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def lock_digest(path: Path) -> str:
    # Windows Git checkouts use CRLF for the same Cargo.lock contents.
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def property_value(component: dict, name: str) -> str | None:
    return next((item.get("value") for item in component.get("properties", [])
                 if item.get("name") == name), None)


def validate_bom(bom: dict) -> tuple[dict, list[dict]]:
    if not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.6":
        raise ValueError("Expected CycloneDX 1.6 SBOM")
    metadata = bom.get("metadata")
    root = metadata.get("component") if isinstance(metadata, dict) else None
    components = bom.get("components")
    dependencies = bom.get("dependencies")
    if not isinstance(root, dict) or not root.get("bom-ref") or root.get("name") != "pybun":
        raise ValueError("SBOM lacks PyBun component")
    if not isinstance(components, list) or not components:
        raise ValueError("SBOM has no dependency components")
    if not isinstance(dependencies, list) or not dependencies:
        raise ValueError("SBOM has no dependency graph")
    for component in [root, *components]:
        if not isinstance(component, dict) or component.get("type") not in ("application", "library"):
            raise ValueError("SBOM has malformed component")
        if not all(isinstance(component.get(key), str) and component[key] for key in ("bom-ref", "name", "version")):
            raise ValueError("SBOM component identity is incomplete")
        if not isinstance(component.get("purl"), str) or not component["purl"].startswith("pkg:cargo/"):
            raise ValueError("SBOM component lacks a Cargo package identifier")
        for item in component.get("hashes", []):
            if not isinstance(item, dict) or item.get("alg") != "SHA-256" or not re.fullmatch(r"[0-9a-f]{64}", str(item.get("content"))):
                raise ValueError("SBOM component has invalid SHA-256 evidence")
    refs = {item["bom-ref"] for item in [root, *components]}
    if None in refs or len(refs) != len(components) + 1:
        raise ValueError("SBOM component references are missing or duplicate")
    graph_refs = {item.get("ref") for item in dependencies if isinstance(item, dict)}
    if graph_refs != refs:
        raise ValueError("SBOM graph does not describe every component")
    for item in dependencies:
        if not isinstance(item, dict) or not isinstance(item.get("dependsOn"), list) or not set(item["dependsOn"]) <= refs:
            raise ValueError("SBOM graph has missing dependency references")
    if not next(item["dependsOn"] for item in dependencies if item["ref"] == root["bom-ref"]):
        raise ValueError("SBOM root has no dependencies")
    return root, components


def cargo_metadata(no_default_features: bool) -> dict:
    # Keep host-side build/proc-macro edges when cross compiling. The build
    # messages below select the packages actually compiled for this target.
    command = ["cargo", "metadata", "--format-version=1", "--locked"]
    if no_default_features:
        command.append("--no-default-features")
    return json.loads(subprocess.run(command, check=True, capture_output=True, text=True).stdout)


def build(args: argparse.Namespace) -> None:
    metadata = json.loads(args.metadata.read_text()) if args.metadata else cargo_metadata(args.no_default_features)
    packages = {item["id"]: item for item in metadata["packages"]}
    nodes = {item["id"]: item for item in metadata["resolve"]["nodes"]}
    root_id = metadata["resolve"]["root"]
    compiled = set()
    for line in args.messages.read_text().splitlines():
        message = json.loads(line)
        if message.get("reason") == "compiler-artifact":
            compiled.add(message["package_id"])
    if root_id not in compiled:
        raise ValueError("PyBun was not present in the release build output")
    if args.artifact.name != f"pybun-{args.target}" + (".zip" if args.target.endswith("-windows-msvc") else ".tar.gz"):
        raise ValueError("Artifact name and release target disagree")
    if not args.artifact.is_file():
        raise ValueError(f"Missing release artifact: {args.artifact}")

    lock = tomllib.loads(args.lockfile.read_text())
    checksums = {(item["name"], item["version"]): item.get("checksum")
                 for item in lock["package"]}
    if (packages[root_id]["name"], packages[root_id]["version"]) not in checksums:
        raise ValueError("Cargo metadata does not match Cargo.lock")

    # Cargo metadata supplies resolved edges; compiler-artifact messages restrict
    # that graph to crates the release build actually compiled, excluding dev-only
    # and inactive optional dependencies.
    reachable = {root_id}
    edges = {}
    queue = [root_id]
    for package_id in queue:
        dependencies = {
            item["pkg"] for item in nodes[package_id]["deps"]
            if item["pkg"] in compiled
            and any(kind.get("kind") != "dev" for kind in item["dep_kinds"])
        }
        edges[package_id] = dependencies
        for dependency in sorted(dependencies):
            if dependency not in reachable:
                reachable.add(dependency)
                queue.append(dependency)
    if not edges[root_id] or not any(edges[package_id] for package_id in reachable - {root_id}):
        raise ValueError("Release build has no meaningful direct and transitive crate inventory")

    def reference(package_id: str) -> str:
        package = packages[package_id]
        return f"pkg:cargo/{package['name']}@{package['version']}?target={args.target}"

    root_package = packages[root_id]
    root = {
        "type": "application", "name": "pybun", "version": root_package["version"],
        "bom-ref": reference(root_id), "purl": f"pkg:cargo/pybun@{root_package['version']}",
        "hashes": [{"alg": "SHA-256", "content": digest(args.artifact)}],
        "properties": [
            {"name": "pybun:release_target", "value": args.target},
            {"name": "pybun:cargo_lock_sha256", "value": lock_digest(args.lockfile)},
            {"name": "pybun:archive", "value": args.artifact.name},
        ],
    }
    components = []
    for package_id in sorted(reachable - {root_id}, key=reference):
        package = packages[package_id]
        checksum = checksums.get((package["name"], package["version"]))
        if checksum is None and str(package.get("source") or "").startswith("registry+"):
            raise ValueError(f"Missing Cargo.lock checksum for {package['name']}")
        component = {
            "type": "library", "name": package["name"], "version": package["version"],
            "bom-ref": reference(package_id), "purl": f"pkg:cargo/{package['name']}@{package['version']}",
        }
        if checksum:
            component["hashes"] = [{"alg": "SHA-256", "content": checksum}]
        components.append(component)
    dependencies = [
        {"ref": reference(package_id), "dependsOn": sorted(reference(dep) for dep in edges[package_id])}
        for package_id in sorted(reachable, key=reference)
    ]
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": root}, "components": components, "dependencies": dependencies,
    }
    validate_bom(bom)
    args.output.write_text(json.dumps(bom, indent=2, sort_keys=True) + "\n")


def merge(args: argparse.Namespace) -> None:
    archives = {item.name: item for item in args.artifacts_dir.rglob("*")
                if item.is_file() and (item.name.endswith(".tar.gz") or item.name.endswith(".zip"))}
    if not archives:
        raise ValueError("No release archives were found")
    roots = []
    components = []
    dependencies = []
    targets = set()
    lock_digest = None
    version = None
    for path in args.input:
        bom = json.loads(path.read_text())
        root, target_components = validate_bom(bom)
        target = property_value(root, "pybun:release_target")
        archive = property_value(root, "pybun:archive")
        lock = property_value(root, "pybun:cargo_lock_sha256")
        if not target or target in targets or not archive or archive not in archives:
            raise ValueError(f"SBOM target or archive is missing/duplicate: {path}")
        if not isinstance(lock, str) or not re.fullmatch(r"[0-9a-f]{64}", lock):
            raise ValueError(f"SBOM lacks a valid Cargo.lock digest: {path}")
        if root.get("hashes") != [{"alg": "SHA-256", "content": digest(archives[archive])}]:
            raise ValueError(f"SBOM archive digest differs from {archive}")
        if lock_digest is not None and lock != lock_digest:
            raise ValueError("SBOM targets use different Cargo.lock contents")
        if version is not None and root.get("version") != version:
            raise ValueError("SBOM targets use different PyBun versions")
        targets.add(target)
        lock_digest, version = lock, root["version"]
        roots.append(root)
        components.extend(target_components)
        dependencies.extend(bom["dependencies"])
    if {property_value(root, "pybun:archive") for root in roots} != set(archives):
        raise ValueError("Every release archive requires its own build SBOM")
    release_root = {"type": "application", "name": "pybun", "version": version,
                    "bom-ref": f"pkg:cargo/pybun@{version}", "purl": f"pkg:cargo/pybun@{version}"}
    combined = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                "metadata": {"component": release_root},
                "components": sorted([*roots, *components], key=lambda item: item["bom-ref"]),
                "dependencies": [{"ref": release_root["bom-ref"],
                                  "dependsOn": sorted(root["bom-ref"] for root in roots)},
                                 *dependencies]}
    validate_bom(combined)
    args.output.write_text(json.dumps(combined, indent=2, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build_parser = sub.add_parser("build")
    build_parser.add_argument("--metadata", type=Path)
    build_parser.add_argument("--messages", required=True, type=Path)
    build_parser.add_argument("--lockfile", required=True, type=Path)
    build_parser.add_argument("--artifact", required=True, type=Path)
    build_parser.add_argument("--target", required=True)
    build_parser.add_argument("--no-default-features", action="store_true")
    build_parser.add_argument("--output", required=True, type=Path)
    merge_parser = sub.add_parser("merge")
    merge_parser.add_argument("--input", required=True, type=Path, nargs="+")
    merge_parser.add_argument("--artifacts-dir", required=True, type=Path)
    merge_parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "build":
            build(args)
        else:
            merge(args)
    except (KeyError, TypeError, ValueError, OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"SBOM generation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
