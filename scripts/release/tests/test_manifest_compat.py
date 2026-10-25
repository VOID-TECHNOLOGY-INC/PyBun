import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import generate_manifest as manifest
import verify_security_artifacts as verify


class ManifestCompatibilityTests(unittest.TestCase):
    def archive(self, root, target, machine):
        header = b"\x7fELF\x02\x01\x01" + b"\0" * 9 + struct.pack("<HH", 3, machine)
        path = root / f"pybun-{target}.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            entry = tarfile.TarInfo(f"pybun-{target}/pybun")
            entry.size = len(header)
            archive.addfile(entry, io.BytesIO(header))
        return path

    def generate(self, root):
        with patch.object(sys, "argv", ["generate_manifest.py", "--assets-dir", str(root),
                          "--version", "0.2.5", "--channel", "stable", "--base-url",
                          "https://example.org", "--output", str(root / "manifest.json"),
                          "--checksums", str(root / "SHA256SUMS")]):
            manifest.main()
        return json.loads((root / "manifest.json").read_text())

    def test_gnu_requirements_are_derived_independently_from_each_elf(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.archive(root, "x86_64-unknown-linux-gnu", 62)
            self.archive(root, "aarch64-unknown-linux-gnu", 183)
            def readelf(command, **kwargs):
                data = Path(command[-1]).read_bytes()
                version = "2.35" if struct.unpack_from("<H", data, 18)[0] == 183 else "2.34"
                output = ("Version needs section '.gnu.version_r' contains 1 entry:\n"
                          "  File: libc.so.6  Cnt: 3\n"
                          f"  Name: GLIBC_2.9\n  Name: GLIBC_{version}\n  Name: GLIBC_2.17\n")
                return subprocess.CompletedProcess(command, 0, output, "")
            with patch("subprocess.run", side_effect=readelf) as inspect:
                result = self.generate(root)
            assets = {a["target"]: a for a in result["assets"]}
            self.assertEqual(assets["x86_64-unknown-linux-gnu"]["compat"]["min_glibc"], "2.34")
            self.assertEqual(assets["aarch64-unknown-linux-gnu"]["compat"]["min_glibc"], "2.35")
            self.assertEqual(inspect.call_count, 2)

    def test_wrong_architecture_fails_before_manifest_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.archive(root, "aarch64-unknown-linux-gnu", 62)
            with self.assertRaisesRegex(ValueError, "ELF"):
                self.generate(root)
            self.assertFalse((root / "manifest.json").exists())

    def test_missing_or_unreadable_version_requirements_fail_closed(self):
        for output in ["No version information found in this file.",
                       "Version definition section '.gnu.version_d':\n Name: GLIBC_9.99\n"]:
            with self.subTest(output=output), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.archive(root, "x86_64-unknown-linux-gnu", 62)
                with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, output, "")):
                    with self.assertRaisesRegex(ValueError, "GLIBC"):
                        self.generate(root)
                self.assertFalse((root / "manifest.json").exists())

    def test_musl_asset_does_not_require_elf_inspection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pybun-x86_64-unknown-linux-musl.tar.gz").write_bytes(b"fixture")
            with patch("subprocess.run") as inspect:
                result = self.generate(root)
            self.assertEqual(result["assets"][0]["compat"], {"libc": "musl"})
            inspect.assert_not_called()

    def test_release_verification_rejects_a_false_glibc_declaration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self.archive(root, "x86_64-unknown-linux-gnu", 62)
            signature = Path(str(artifact) + ".minisig")
            signature.write_text("fixture")
            public_key = root / "release.pub"
            public_key.write_text("fixture")
            asset = {"name": artifact.name, "url": "https://example.org/" + artifact.name,
                     "sha256": verify.digest(artifact), "target": "x86_64-unknown-linux-gnu",
                     "compat": {"libc": "glibc", "min_glibc": "2.31"},
                     "signature": {"url": "https://example.org/" + signature.name}}
            with patch("generate_manifest.glibc_requirement", return_value="2.34"), self.assertRaisesRegex(ValueError, "GLIBC"):
                verify.verify_assets(root, [asset], None, public_key)


if __name__ == "__main__":
    unittest.main()
