import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import generate_package_managers as gpm  # noqa: E402


class PackageManagerTests(unittest.TestCase):
    def setUp(self):
        self.manifest = {
            "version": "1.2.3",
            "assets": [
                {
                    "name": "pybun-x86_64-unknown-linux-gnu.tar.gz",
                    "target": "x86_64-unknown-linux-gnu",
                    "url": "https://example.com/linux.tar.gz",
                },
                {
                    "name": "pybun-x86_64-pc-windows-msvc.zip",
                    "target": "x86_64-pc-windows-msvc",
                    "url": "https://example.com/windows.zip",
                },
            ],
        }
        self.checksums = {
            "pybun-x86_64-unknown-linux-gnu.tar.gz": "a" * 64,
            "pybun-x86_64-pc-windows-msvc.zip": "b" * 64,
        }

    def test_parse_checksums(self):
        mapping = gpm.parse_checksums("aaa  one.tar.gz\nbbb  two.tar.gz\n")
        self.assertEqual(mapping["one.tar.gz"], "aaa")
        self.assertEqual(mapping["two.tar.gz"], "bbb")

    def test_resolve_asset(self):
        asset = gpm.resolve_asset(
            "x86_64-unknown-linux-gnu", self.manifest, self.checksums
        )
        self.assertEqual(asset["sha256"], "a" * 64)
        self.assertEqual(asset["url"], "https://example.com/linux.tar.gz")

    def test_build_homebrew_formula(self):
        assets = {
            "macos_arm": {"url": "https://example.com/macos-arm.tar.gz", "sha256": "c" * 64},
            "macos_x86": {"url": "https://example.com/macos-x86.tar.gz", "sha256": "d" * 64},
            "linux_arm": {"url": "https://example.com/linux-arm.tar.gz", "sha256": "e" * 64},
            "linux_x86": {"url": "https://example.com/linux-x86.tar.gz", "sha256": "f" * 64},
        }
        formula = gpm.build_homebrew_formula("1.2.3", assets)
        self.assertIn('version "1.2.3"', formula)
        self.assertIn("HOMEBREW_PYBUN_TEST_TARBALL", formula)
        self.assertIn("https://example.com/macos-arm.tar.gz", formula)

    def test_build_scoop_manifest(self):
        manifest = gpm.build_scoop_manifest(
            "1.2.3",
            {
                "name": "pybun-x86_64-pc-windows-msvc.zip",
                "url": "https://example.com/windows.zip",
                "sha256": "b" * 64,
                "extract_dir": "pybun-x86_64-pc-windows-msvc",
            },
        )
        self.assertEqual(manifest["version"], "1.2.3")
        self.assertEqual(manifest["architecture"]["64bit"]["hash"], "b" * 64)

    def test_build_winget_manifest(self):
        manifest = gpm.build_winget_manifest(
            "1.2.3",
            {
                "url": "https://example.com/windows.zip",
                "sha256": "b" * 64,
                "extract_dir": "pybun-x86_64-pc-windows-msvc",
            },
        )
        self.assertIn("PackageVersion: 1.2.3", manifest)
        self.assertIn("InstallerUrl: https://example.com/windows.zip", manifest)
        self.assertIn("InstallerSha256: " + "b" * 64, manifest)


if __name__ == "__main__":
    unittest.main()
