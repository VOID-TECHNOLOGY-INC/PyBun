from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "generate_sbom.py"


class ReleaseSbomTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.artifact = self.root / "pybun-aarch64-apple-darwin.tar.gz"
        self.artifact.write_bytes(b"release archive")
        packages = [
            {"id": "pybun", "name": "pybun", "version": "0.2.6", "source": None},
            {"id": "direct", "name": "clap", "version": "4.5.0", "source": "registry+https://github.com/rust-lang/crates.io-index"},
            {"id": "transitive", "name": "clap_builder", "version": "4.5.0", "source": "registry+https://github.com/rust-lang/crates.io-index"},
            {"id": "dev-only", "name": "proptest", "version": "1.0.0", "source": "registry+https://github.com/rust-lang/crates.io-index"},
        ]
        graph = [
            {"id": "pybun", "deps": [{"pkg": "direct", "dep_kinds": [{"kind": None}]}]},
            {"id": "direct", "deps": [{"pkg": "transitive", "dep_kinds": [{"kind": None}]}, {"pkg": "dev-only", "dep_kinds": [{"kind": "dev"}]}]},
            {"id": "transitive", "deps": []},
            {"id": "dev-only", "deps": []},
        ]
        self.metadata = self.root / "metadata.json"
        self.metadata.write_text(json.dumps({"packages": packages, "resolve": {"root": "pybun", "nodes": graph}}))
        self.messages = self.root / "messages.jsonl"
        self.messages.write_text("\n".join(json.dumps({"reason": "compiler-artifact", "package_id": name, "features": []}) for name in ["pybun", "direct", "transitive", "dev-only"]))
        self.lock = self.root / "Cargo.lock"
        self.lock.write_text(
            'version = 4\n'
            '[[package]]\nname = "pybun"\nversion = "0.2.6"\n'
            '[[package]]\nname = "clap"\nversion = "4.5.0"\n'
            f'checksum = "{"a" * 64}"\n'
            '[[package]]\nname = "clap_builder"\nversion = "4.5.0"\n'
            f'checksum = "{"b" * 64}"\n'
        )
        self.output = self.root / "target.sbom.json"

    def generate(self):
        return subprocess.run([sys.executable, str(SCRIPT), "build", "--metadata", str(self.metadata), "--messages", str(self.messages), "--lockfile", str(self.lock), "--artifact", str(self.artifact), "--target", "aarch64-apple-darwin", "--output", str(self.output)], capture_output=True, text=True, check=False)

    def test_release_inventory_tracks_actual_compiled_dependencies(self):
        result = self.generate()
        self.assertEqual(result.returncode, 0, result.stderr)
        bom = json.loads(self.output.read_text())
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        self.assertEqual(bom["specVersion"], "1.6")
        self.assertRegex(bom["serialNumber"], r"^urn:uuid:[0-9a-f-]{36}$")
        by_name = {component["name"]: component for component in bom["components"]}
        self.assertEqual(set(by_name), {"clap", "clap_builder"})
        self.assertEqual(by_name["clap"]["version"], "4.5.0")
        self.assertEqual(by_name["clap"]["hashes"][0]["content"], "a" * 64)
        self.assertEqual(bom["metadata"]["component"]["hashes"][0]["content"], hashlib.sha256(self.artifact.read_bytes()).hexdigest())
        self.assertTrue(all(dependency["ref"] in {entry["bom-ref"] for entry in [bom["metadata"]["component"], *bom["components"]]} for dependency in bom["dependencies"]))
        self.assertIn(by_name["clap_builder"]["bom-ref"], next(d["dependsOn"] for d in bom["dependencies"] if d["ref"] == by_name["clap"]["bom-ref"]))

    def test_missing_compiled_transitive_package_fails(self):
        self.messages.write_text(self.messages.read_text().replace('{"reason": "compiler-artifact", "package_id": "transitive", "features": []}\n', ''))
        self.assertNotEqual(self.generate().returncode, 0)
        self.assertFalse(self.output.exists())

    def test_merged_sbom_binds_each_target_and_archive(self):
        self.assertEqual(self.generate().returncode, 0)
        first = self.output
        other = self.root / "pybun-x86_64-pc-windows-msvc.zip"
        other.write_bytes(b"different release archive")
        self.artifact = other
        self.output = self.root / "windows.sbom.json"
        self.lock.write_bytes(self.lock.read_bytes().replace(b"\n", b"\r\n"))
        result = subprocess.run([sys.executable, str(SCRIPT), "build", "--metadata", str(self.metadata), "--messages", str(self.messages), "--lockfile", str(self.lock), "--artifact", str(other), "--target", "x86_64-pc-windows-msvc", "--output", str(self.output)], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        merged = self.root / "merged.json"
        command = [sys.executable, str(SCRIPT), "merge", "--input", str(first), str(self.output), "--artifacts-dir", str(self.root), "--output", str(merged)]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        bom = json.loads(merged.read_text())
        self.assertRegex(bom["serialNumber"], r"^urn:uuid:[0-9a-f-]{36}$")
        self.assertEqual(len(bom["components"]), 6)
        self.assertEqual(bom["metadata"]["component"]["bom-ref"], "pkg:cargo/pybun@0.2.6")
        names = {entry["bom-ref"] for entry in bom["components"]}
        self.assertTrue(any("aarch64-apple-darwin" in name for name in names))
        self.assertTrue(any("x86_64-pc-windows-msvc" in name for name in names))
        other.write_bytes(b"tampered archive")
        self.assertNotEqual(subprocess.run(command, capture_output=True, check=False).returncode, 0)

    def test_empty_placeholder_rejected_when_merging(self):
        self.output.write_text('{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{}}')
        result = subprocess.run([sys.executable, str(SCRIPT), "merge", "--input", str(self.output), "--artifacts-dir", str(self.root), "--output", str(self.root / "combined.json")], capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "combined.json").exists())

    def test_malformed_component_and_missing_lock_evidence_fail(self):
        self.assertEqual(self.generate().returncode, 0)
        valid = json.loads(self.output.read_text())
        output = self.root / "combined.json"
        command = [sys.executable, str(SCRIPT), "merge", "--input", str(self.output), "--artifacts-dir", str(self.root), "--output", str(output)]
        invalid = json.loads(json.dumps(valid))
        invalid["components"][0] = {"bom-ref": valid["components"][0]["bom-ref"]}
        self.output.write_text(json.dumps(invalid))
        self.assertNotEqual(subprocess.run(command, capture_output=True, check=False).returncode, 0)
        self.assertFalse(output.exists())
        invalid = json.loads(json.dumps(valid))
        invalid["metadata"]["component"]["properties"] = [item for item in invalid["metadata"]["component"]["properties"] if item["name"] != "pybun:cargo_lock_sha256"]
        self.output.write_text(json.dumps(invalid))
        self.assertNotEqual(subprocess.run(command, capture_output=True, check=False).returncode, 0)
        self.assertFalse(output.exists())
        invalid = json.loads(json.dumps(valid))
        del invalid["serialNumber"]
        self.output.write_text(json.dumps(invalid))
        self.assertNotEqual(subprocess.run(command, capture_output=True, check=False).returncode, 0)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
