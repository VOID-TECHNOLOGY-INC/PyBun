from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "verify_security_artifacts.py"
SBOM = ROOT / "generate_sbom.py"
MANIFEST = ROOT / "generate_manifest.py"
PROVENANCE = ROOT / "generate_provenance.py"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SecurityArtifactsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.artifacts = self.base / "artifacts"
        self.artifacts.mkdir()
        self.asset = self.artifacts / "pybun-x86_64-unknown-linux-musl.tar.gz"
        self.asset.write_bytes(b"signed-release-archive")
        self.public_key = self.base / "release.pub"
        private_key = self.base / "release.key"
        subprocess.run(["minisign", "-G", "-W", "-p", str(self.public_key), "-s", str(private_key), "-c", "test"], check=True, capture_output=True)
        self.signature = self.asset.with_name(self.asset.name + ".minisig")
        subprocess.run(["minisign", "-Sm", str(self.asset), "-s", str(private_key)], check=True, capture_output=True)
        self.sbom = self.base / "pybun-sbom.json"
        self.provenance = self.base / "pybun-provenance.json"
        self.manifest = self.base / "pybun-release.json"
        self.checksums = self.base / "SHA256SUMS"
        self.make_generated_sbom()
        subprocess.run([sys.executable, str(PROVENANCE), "--assets-dir", str(self.artifacts), "--output", str(self.provenance)], check=True, capture_output=True)
        subprocess.run([sys.executable, str(MANIFEST), "--assets-dir", str(self.artifacts), "--version", "0.2.6", "--channel", "stable", "--base-url", "https://example.test/release", "--public-key", str(self.public_key), "--sbom", str(self.sbom), "--provenance", str(self.provenance), "--output", str(self.manifest), "--checksums", str(self.checksums)], check=True, capture_output=True)

    def make_generated_sbom(self):
        metadata = self.base / "cargo-metadata.json"
        ids = ["pybun", "clap", "clap_builder"]
        metadata.write_text(json.dumps({"packages": [{"id": name, "name": name, "version": "0.2.6" if name == "pybun" else "1.0.0", "source": None if name == "pybun" else "registry+crates.io"} for name in ids], "resolve": {"root": "pybun", "nodes": [{"id": "pybun", "deps": [{"pkg": "clap", "dep_kinds": [{"kind": None}]}]}, {"id": "clap", "deps": [{"pkg": "clap_builder", "dep_kinds": [{"kind": None}]}]}, {"id": "clap_builder", "deps": []}]}}))
        messages = self.base / "build.jsonl"
        messages.write_text("\n".join(json.dumps({"reason": "compiler-artifact", "package_id": name}) for name in ids))
        lock = self.base / "Cargo.lock"
        lock.write_text('version = 4\n[[package]]\nname="pybun"\nversion="0.2.6"\n' + ''.join(f'[[package]]\nname="{name}"\nversion="1.0.0"\nchecksum="{"a" * 64}"\n' for name in ids[1:]))
        per_target = self.base / "target.sbom.json"
        subprocess.run([sys.executable, str(SBOM), "build", "--metadata", str(metadata), "--messages", str(messages), "--lockfile", str(lock), "--artifact", str(self.asset), "--target", "x86_64-unknown-linux-musl", "--output", str(per_target)], check=True, capture_output=True)
        subprocess.run([sys.executable, str(SBOM), "merge", "--input", str(per_target), "--artifacts-dir", str(self.artifacts), "--output", str(self.sbom)], check=True, capture_output=True)

    def verify(self, *, key=True, checksums=True):
        command = [sys.executable, str(VERIFY), "--artifacts-dir", str(self.artifacts), "--manifest", str(self.manifest), "--sbom", str(self.sbom), "--provenance", str(self.provenance)]
        if key:
            command.extend(["--public-key", str(self.public_key)])
        if checksums:
            command.extend(["--checksums", str(self.checksums)])
        return subprocess.run(command, check=False, capture_output=True, text=True)

    def manifest_data(self):
        return json.loads(self.manifest.read_text())

    def write_manifest(self, value):
        self.manifest.write_text(json.dumps(value))

    def assert_rejected(self, fragment: str):
        result = self.verify()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(fragment.lower(), result.stderr.lower())

    def test_generated_signed_bundle_succeeds(self):
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("assets=1", result.stdout)

    def test_unlisted_unsigned_archive_is_rejected(self):
        (self.artifacts / "pybun-extra.tar.gz").write_bytes(b"unsigned")
        self.assert_rejected("unsigned")

    def test_malformed_gnu_archive_reports_a_concise_error(self):
        bad_archive = self.artifacts / "pybun-x86_64-unknown-linux-gnu.tar.gz"
        self.asset.rename(bad_archive)
        self.signature.unlink()
        subprocess.run(["minisign", "-Sm", str(bad_archive), "-s", str(self.base / "release.key")], check=True, capture_output=True)
        manifest = self.manifest_data()
        asset = manifest["assets"][0]
        asset["name"] = bad_archive.name
        asset["url"] = "https://example.test/release/" + bad_archive.name
        asset["target"] = "x86_64-unknown-linux-gnu"
        asset["compat"] = {"libc": "glibc", "min_glibc": "2.34"}
        asset["signature"]["url"] = "https://example.test/release/" + bad_archive.name + ".minisig"
        asset["signature"]["value"] = Path(str(bad_archive) + ".minisig").read_text().strip()
        self.write_manifest(manifest)
        self.checksums.write_text(f"{sha256(bad_archive)}  {bad_archive.name}\n")
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("[ERROR]", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_empty_or_missing_assets_fail(self):
        data = self.manifest_data()
        self.write_manifest({})
        self.assert_rejected("manifest")
        data["assets"] = []
        self.write_manifest(data)
        self.assert_rejected("assets")

    def test_missing_manifest_fails(self):
        self.manifest.unlink()
        self.assert_rejected("manifest")

    def test_missing_trust_root_fails(self):
        result = self.verify(key=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("public key", result.stderr.lower())

    def test_missing_or_invalid_manifest_digest_fails(self):
        data = self.manifest_data()
        del data["assets"][0]["sha256"]
        self.write_manifest(data)
        self.assert_rejected("sha256")
        data["assets"][0]["sha256"] = "not-a-digest"
        self.write_manifest(data)
        self.assert_rejected("sha256")

    def test_requested_checksum_file_must_be_complete(self):
        self.checksums.write_text("")
        self.assert_rejected("checksums")
        self.checksums.write_text("a" * 64 + "  wrong.tar.gz\n")
        self.assert_rejected("checksum")
        self.checksums.unlink()
        self.assert_rejected("checksums")

    def test_requested_key_must_exist_and_verify_real_signature(self):
        self.public_key.unlink()
        self.assert_rejected("public key")
        self.public_key.write_text("")
        self.assert_rejected("public key")

    def test_forged_matching_signature_text_is_rejected(self):
        self.signature.write_text("trusted-signature")
        data = self.manifest_data()
        data["assets"][0]["signature"]["value"] = "trusted-signature"
        self.write_manifest(data)
        self.assert_rejected("signature")

    def test_missing_signature_or_wrong_trust_root_is_rejected(self):
        signature = self.signature.read_text()
        self.signature.unlink()
        self.assert_rejected("signature")
        self.signature.write_text(signature)
        other_public = self.base / "other.pub"
        subprocess.run(["minisign", "-G", "-W", "-p", str(other_public), "-s", str(self.base / "other.key"), "-c", "other"], check=True, capture_output=True)
        self.public_key.write_text(other_public.read_text())
        manifest = self.manifest_data()
        manifest["assets"][0]["signature"]["public_key"] = self.public_key.read_text().strip()
        self.write_manifest(manifest)
        self.assert_rejected("signature")

    def test_provenance_subjects_must_match_assets(self):
        data = json.loads(self.provenance.read_text())
        data["subject"][0]["digest"]["sha256"] = "b" * 64
        self.provenance.write_text(json.dumps(data))
        manifest = self.manifest_data()
        manifest["provenance"]["sha256"] = sha256(self.provenance)
        self.write_manifest(manifest)
        self.assert_rejected("provenance")

    def test_provenance_subject_name_must_match(self):
        data = json.loads(self.provenance.read_text())
        data["subject"][0]["name"] = "another-release.tar.gz"
        self.provenance.write_text(json.dumps(data))
        manifest = self.manifest_data()
        manifest["provenance"]["sha256"] = sha256(self.provenance)
        self.write_manifest(manifest)
        self.assert_rejected("provenance")

    def test_attachment_digest_and_url_must_match(self):
        manifest = self.manifest_data()
        manifest["sbom"]["url"] = "https://example.test/wrong.json"
        self.write_manifest(manifest)
        self.assert_rejected("sbom")
        manifest["sbom"]["url"] = "https://example.test/release/pybun-sbom.json"
        manifest["sbom"]["sha256"] = "0" * 64
        self.write_manifest(manifest)
        self.assert_rejected("sbom")

    def test_metadata_only_sbom_is_rejected(self):
        self.sbom.write_text('{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{}}')
        manifest = self.manifest_data()
        manifest["sbom"]["sha256"] = sha256(self.sbom)
        self.write_manifest(manifest)
        self.assert_rejected("sbom")


if __name__ == "__main__":
    unittest.main()
