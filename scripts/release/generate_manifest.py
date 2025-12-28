#!/usr/bin/env python3
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def sha256sum(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def detect_assets(assets_dir: Path):
    candidates = []
    for path in assets_dir.rglob("*"):
        if not path.is_file():
            continue
        if path.name.endswith(".tar.gz") or path.name.endswith(".zip"):
            candidates.append(path)
    return sorted(candidates, key=lambda p: p.name)


def target_from_name(filename: str) -> str | None:
    if filename.endswith(".tar.gz"):
        base = filename[: -len(".tar.gz")]
    elif filename.endswith(".zip"):
        base = filename[: -len(".zip")]
    else:
        return None
    if base.startswith("pybun-"):
        return base[len("pybun-") :]
    return base


def read_optional_text(path: Path | None) -> str | None:
    if path is None:
        return None
    if not path.exists():
        return None
    return path.read_text().strip()


def attachment_entry(path: Path | None, base_url: str):
    if path is None or not path.exists():
        return None
    digest = sha256sum(path)
    return {
        "name": path.name,
        "url": f"{base_url}/{path.name}",
        "sha256": digest,
    }


def write_sha256sums(output: Path, assets):
    lines = [f"{asset['sha256']}  {asset['name']}" for asset in assets]
    output.write_text("\n".join(lines) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate PyBun release manifest and checksums.")
    parser.add_argument("--assets-dir", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--channel", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--output", default="pybun-release.json", type=Path)
    parser.add_argument("--checksums", default="SHA256SUMS", type=Path)
    parser.add_argument("--public-key", type=Path)
    parser.add_argument("--signature-type", default="minisign")
    parser.add_argument("--signature-ext", default=".minisig")
    parser.add_argument("--published-at")
    parser.add_argument("--release-url")
    parser.add_argument("--sbom", type=Path)
    parser.add_argument("--provenance", type=Path)
    parser.add_argument("--release-notes", type=Path)
    args = parser.parse_args()

    assets_dir = args.assets_dir
    base_url = args.base_url.rstrip("/")
    signature_ext = args.signature_ext
    if signature_ext and not signature_ext.startswith("."):
        signature_ext = f".{signature_ext}"

    published_at = args.published_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    public_key = read_optional_text(args.public_key)

    assets = []
    for path in detect_assets(assets_dir):
        name = path.name
        target = target_from_name(name)
        if not target:
            continue
        digest = sha256sum(path)
        asset = {
            "name": name,
            "target": target,
            "url": f"{base_url}/{name}",
            "sha256": digest,
        }
        if signature_ext:
            sig_path = path.with_name(path.name + signature_ext)
            if sig_path.exists():
                signature = {
                    "type": args.signature_type,
                    "value": sig_path.read_text().strip(),
                    "url": f"{base_url}/{sig_path.name}",
                }
                if public_key:
                    signature["public_key"] = public_key
                asset["signature"] = signature
        assets.append(asset)

    if not assets:
        raise SystemExit(f"No release assets found under {assets_dir}")

    write_sha256sums(args.checksums, assets)

    manifest = {
        "version": args.version,
        "channel": args.channel,
        "published_at": published_at,
        "assets": assets,
        "release_url": args.release_url,
        "release_notes": attachment_entry(args.release_notes, base_url),
        "sbom": attachment_entry(args.sbom, base_url),
        "provenance": attachment_entry(args.provenance, base_url),
    }

    manifest = {key: value for key, value in manifest.items() if value is not None}
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
