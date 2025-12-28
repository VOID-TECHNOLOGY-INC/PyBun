#!/usr/bin/env python3
"""
Verify release artifacts have security metadata (SBOM, provenance, signatures).

This is intended to be run in CI after the release artifacts/metadata are generated.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def find_file(root: Path, filename: str) -> Optional[Path]:
    for candidate in root.rglob("*"):
        if candidate.is_file() and candidate.name == filename:
            return candidate
    return None


def parse_checksums(path: Path) -> dict[str, str]:
    mapping: dict[str, str] = {}
    if not path.exists():
        return mapping
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            digest, name = parts[0], parts[-1]
            mapping[name] = digest
    return mapping


def attachment_name(entry: dict) -> Optional[str]:
    url = entry.get("url")
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.path:
        return Path(parsed.path).name
    return None


def validate_attachment(path: Path, entry: dict, label: str, errors: list[str]) -> None:
    if not path.exists():
        errors.append(f"Missing {label}: {path}")
        return
    expected = entry.get("sha256")
    if expected:
        actual = sha256(path)
        if actual != expected:
            errors.append(
                f"{label} checksum mismatch for {path.name}: expected {expected}, got {actual}"
            )


def validate_assets(
    artifacts_dir: Path,
    manifest: dict,
    checksums: dict[str, str],
    public_key: Optional[str],
    errors: list[str],
) -> None:
    assets = manifest.get("assets") or []
    if not assets:
        errors.append("No assets listed in manifest")
        return

    for asset in assets:
        name = asset.get("name")
        if not name:
            errors.append("Asset missing name")
            continue
        artifact_path = find_file(artifacts_dir, name)
        if not artifact_path:
            errors.append(f"Artifact not found for {name} under {artifacts_dir}")
            continue

        expected_sha = asset.get("sha256")
        if expected_sha:
            actual_sha = sha256(artifact_path)
            if expected_sha != actual_sha:
                errors.append(
                    f"Checksum mismatch for {name}: expected {expected_sha}, got {actual_sha}"
                )

        if checksums:
            checksum_file_value = checksums.get(name)
            if checksum_file_value:
                if expected_sha and checksum_file_value != expected_sha:
                    errors.append(
                        f"Checksum file mismatch for {name}: manifest={expected_sha}, checksums={checksum_file_value}"
                    )
            else:
                errors.append(f"Missing checksum entry for {name}")

        signature = asset.get("signature")
        if not signature:
            errors.append(f"Missing signature for asset {name}")
            continue
        sig_filename = attachment_name(signature) or f"{name}.minisig"
        signature_path = find_file(artifacts_dir, sig_filename)
        if not signature_path:
            errors.append(f"Missing signature file for {name}: expected {sig_filename}")
        else:
            signature_content = signature_path.read_text().strip()
            if not signature_content:
                errors.append(f"Empty signature for {name} at {signature_path}")
            elif signature.get("value") and signature["value"].strip() != signature_content:
                errors.append(
                    f"Signature content mismatch for {name}: manifest value differs from file"
                )
        if public_key and signature.get("public_key") and signature["public_key"] != public_key:
            errors.append(
                f"Signature public key mismatch for {name}: manifest key does not match provided key"
            )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate release security artifacts (SBOM, provenance, signatures)."
    )
    parser.add_argument("--artifacts-dir", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--sbom", required=True, type=Path)
    parser.add_argument("--provenance", required=True, type=Path)
    parser.add_argument("--checksums", required=False, type=Path)
    parser.add_argument("--public-key", required=False, type=Path)
    args = parser.parse_args()

    errors: list[str] = []
    if not args.manifest.exists():
        errors.append(f"Missing manifest: {args.manifest}")
    if not args.artifacts_dir.exists():
        errors.append(f"Missing artifacts directory: {args.artifacts_dir}")
    if not args.sbom.exists():
        errors.append(f"Missing SBOM: {args.sbom}")
    if not args.provenance.exists():
        errors.append(f"Missing provenance: {args.provenance}")
    if args.checksums and not args.checksums.exists():
        errors.append(f"Missing checksums file: {args.checksums}")

    public_key_value = (
        args.public_key.read_text().strip()
        if args.public_key and args.public_key.exists()
        else None
    )
    checksums = parse_checksums(args.checksums) if args.checksums else {}

    manifest: dict = {}
    if args.manifest.exists():
        manifest = json.loads(args.manifest.read_text())

    if manifest:
        sbom_entry = manifest.get("sbom")
        if not sbom_entry:
            errors.append("Manifest missing SBOM entry")
        else:
            validate_attachment(args.sbom, sbom_entry, "SBOM", errors)

        provenance_entry = manifest.get("provenance")
        if not provenance_entry:
            errors.append("Manifest missing provenance entry")
        else:
            validate_attachment(args.provenance, provenance_entry, "provenance", errors)

        validate_assets(args.artifacts_dir, manifest, checksums, public_key_value, errors)

    if errors:
        for error in errors:
            print(f"[ERROR] {error}", file=sys.stderr)
        return 1

    print(
        f"Security artifacts verified: assets={len(manifest.get('assets', []))}, "
        f"sbom={args.sbom.name}, provenance={args.provenance.name}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
