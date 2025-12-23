#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

DESCRIPTION = "Rust-based single-binary Python toolchain."
HOMEPAGE = "https://github.com/pybun/pybun"
LICENSE = "MIT"
PUBLISHER = "VOID TECHNOLOGY INC"
PACKAGE_IDENTIFIER = "PyBun.PyBun"

TARGETS = {
    "macos_arm": "aarch64-apple-darwin",
    "macos_x86": "x86_64-apple-darwin",
    "linux_arm": "aarch64-unknown-linux-gnu",
    "linux_x86": "x86_64-unknown-linux-gnu",
}
WINDOWS_TARGET = "x86_64-pc-windows-msvc"


def parse_checksums(text: str) -> dict[str, str]:
    mapping = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        mapping[parts[1]] = parts[0]
    return mapping


def read_manifest(path: Path) -> dict:
    return json.loads(path.read_text())


def resolve_asset(target: str, manifest: dict, checksums: dict[str, str]) -> dict:
    assets = manifest.get("assets", [])
    asset = next((item for item in assets if item.get("target") == target), None)
    if not asset:
        raise ValueError(f"missing asset for target: {target}")
    name = asset.get("name")
    url = asset.get("url")
    if not name or not url:
        raise ValueError(f"asset missing name/url for target: {target}")
    sha256 = checksums.get(name)
    if not sha256:
        raise ValueError(f"missing checksum for asset: {name}")
    return {
        "name": name,
        "url": url,
        "sha256": sha256,
        "target": target,
    }


def archive_base(name: str) -> str:
    if name.endswith(".tar.gz"):
        return name[: -len(".tar.gz")]
    if name.endswith(".zip"):
        return name[: -len(".zip")]
    return name


def build_homebrew_formula(version: str, assets: dict[str, dict]) -> str:
    macos_arm = assets["macos_arm"]
    macos_x86 = assets["macos_x86"]
    linux_arm = assets["linux_arm"]
    linux_x86 = assets["linux_x86"]

    return f"""# This file is auto-generated. Do not edit by hand.
class Pybun < Formula
  desc "{DESCRIPTION}"
  homepage "{HOMEPAGE}"
  version "{version}"
  license "{LICENSE}"

  if ENV["PYBUN_HOMEBREW_TEST_TARBALL"]
    url ENV["PYBUN_HOMEBREW_TEST_TARBALL"]
    sha256 ENV["PYBUN_HOMEBREW_TEST_SHA256"]
  else
    on_macos do
      if Hardware::CPU.arm?
        url "{macos_arm['url']}"
        sha256 "{macos_arm['sha256']}"
      else
        url "{macos_x86['url']}"
        sha256 "{macos_x86['sha256']}"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "{linux_arm['url']}"
        sha256 "{linux_arm['sha256']}"
      else
        url "{linux_x86['url']}"
        sha256 "{linux_x86['sha256']}"
      end
    end
  end

  def install
    bin.install Dir["pybun-*/pybun"]
  end

  test do
    system "#{{bin}}/pybun", "--version"
  end
end
"""


def build_scoop_manifest(version: str, win_asset: dict) -> dict:
    extract_dir = win_asset["extract_dir"]
    return {
        "version": version,
        "description": DESCRIPTION,
        "homepage": HOMEPAGE,
        "license": LICENSE,
        "architecture": {
            "64bit": {
                "url": win_asset["url"],
                "hash": win_asset["sha256"],
            }
        },
        "bin": "pybun.exe",
        "extract_dir": extract_dir,
        "checkver": {
            "url": f"{HOMEPAGE}/releases/latest",
            "regex": "tag/v([\\d.]+)",
        },
        "autoupdate": {
            "architecture": {
                "64bit": {
                    "url": f"{HOMEPAGE}/releases/download/v$version/{win_asset['name']}"
                }
            }
        },
    }


def build_winget_manifest(version: str, win_asset: dict) -> str:
    extract_dir = win_asset["extract_dir"]
    return f"""PackageIdentifier: {PACKAGE_IDENTIFIER}
PackageVersion: {version}
PackageLocale: en-US
Publisher: {PUBLISHER}
PublisherUrl: {HOMEPAGE}
PublisherSupportUrl: {HOMEPAGE}/issues
PackageName: PyBun
PackageUrl: {HOMEPAGE}
License: {LICENSE}
LicenseUrl: {HOMEPAGE}/blob/main/LICENSE
ShortDescription: {DESCRIPTION}
Moniker: pybun
Tags:
  - python
  - package-manager
Installers:
  - Architecture: x64
    InstallerUrl: {win_asset['url']}
    InstallerSha256: {win_asset['sha256']}
    InstallerType: zip
    NestedInstallerType: portable
    NestedInstallerFiles:
      - RelativeFilePath: {extract_dir}/pybun.exe
        PortableCommandAlias: pybun
ManifestType: singleton
ManifestVersion: 1.4.0
"""


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate package manager manifests.")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--checksums", required=True, type=Path)
    parser.add_argument("--homebrew", type=Path)
    parser.add_argument("--scoop", type=Path)
    parser.add_argument("--winget", type=Path)
    args = parser.parse_args()

    if not args.homebrew and not args.scoop and not args.winget:
        raise SystemExit("at least one output path is required")

    manifest = read_manifest(args.manifest)
    version = manifest.get("version")
    if not version:
        raise SystemExit("manifest missing version")

    checksums = parse_checksums(args.checksums.read_text())

    assets = {}
    for key, target in TARGETS.items():
        assets[key] = resolve_asset(target, manifest, checksums)

    win_asset = resolve_asset(WINDOWS_TARGET, manifest, checksums)
    win_asset["extract_dir"] = archive_base(win_asset["name"])

    if args.homebrew:
        ensure_parent(args.homebrew)
        args.homebrew.write_text(build_homebrew_formula(version, assets))
    if args.scoop:
        ensure_parent(args.scoop)
        scoop_manifest = build_scoop_manifest(version, win_asset)
        args.scoop.write_text(json.dumps(scoop_manifest, indent=2) + "\n")
    if args.winget:
        ensure_parent(args.winget)
        args.winget.write_text(build_winget_manifest(version, win_asset))


if __name__ == "__main__":
    main()
