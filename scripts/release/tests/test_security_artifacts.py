from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "verify_security_artifacts.py"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class SecurityArtifactsTests(unittest.TestCase):
    def make_bundle(self):
        base = Path(tempfile.mkdtemp())
        artifacts = base / "artifacts"
        metadata = base / "metadata"
        artifacts.mkdir(parents=True, exist_ok=True)
        metadata.mkdir(parents=True, exist_ok=True)

        artifact = artifacts / "pybun-x86_64-unknown-linux-gnu.tar.gz"
        artifact.write_bytes(b"artifact-bytes")
        signature = Path(str(artifact) + ".minisig")
        signature.write_text("trusted-signature")

        sbom = metadata / "pybun-sbom.json"
        sbom.write_text('{"sbom": true}')
        provenance = metadata / "pybun-provenance.json"
        provenance.write_text('{"provenance": true}')
        checksums = metadata / "SHA256SUMS"
        public_key = metadata / "pybun-release.pub"
        public_key.write_text("public-key-payload")

        manifest = metadata / "pybun-release.json"
        manifest.write_text(
            json.dumps(
                {
                    "version": "0.1.0",
                    "channel": "stable",
                    "assets": [
                        {
                            "name": artifact.name,
                            "target": "x86_64-unknown-linux-gnu",
                            "url": f"https://example.com/{artifact.name}",
                            "sha256": sha256(artifact),
                            "signature": {
                                "type": "minisign",
                                "value": signature.read_text().strip(),
                                "url": f"https://example.com/{signature.name}",
                                "public_key": public_key.read_text().strip(),
                            },
                        }
                    ],
                    "sbom": {
                        "name": sbom.name,
                        "url": f"https://example.com/{sbom.name}",
                        "sha256": sha256(sbom),
                    },
                    "provenance": {
                        "name": provenance.name,
                        "url": f"https://example.com/{provenance.name}",
                        "sha256": sha256(provenance),
                    },
                }
            )
        )

        checksums.write_text(f"{sha256(artifact)}  {artifact.name}\n")

        return {
            "base": base,
            "artifacts": artifacts,
            "metadata": metadata,
            "artifact": artifact,
            "signature": signature,
            "sbom": sbom,
            "provenance": provenance,
            "manifest": manifest,
            "checksums": checksums,
            "public_key": public_key,
        }

    def run_script(self, bundle: dict[str, Path]):
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--artifacts-dir",
                str(bundle["artifacts"]),
                "--manifest",
                str(bundle["manifest"]),
                "--sbom",
                str(bundle["sbom"]),
                "--provenance",
                str(bundle["provenance"]),
                "--checksums",
                str(bundle["checksums"]),
                "--public-key",
                str(bundle["public_key"]),
            ],
            capture_output=True,
            text=True,
        )

    def test_verify_bundle_success(self):
        bundle = self.make_bundle()
        result = self.run_script(bundle)
        self.assertEqual(
            result.returncode, 0, f"expected success but got {result.stderr}"
        )

    def test_missing_signature_should_fail(self):
        bundle = self.make_bundle()
        bundle["signature"].unlink()
        result = self.run_script(bundle)
        self.assertNotEqual(result.returncode, 0, "missing signature must fail")
        self.assertIn("signature", result.stderr.lower())

    def test_missing_sbom_should_fail(self):
        bundle = self.make_bundle()
        bundle["sbom"].unlink()
        result = self.run_script(bundle)
        self.assertNotEqual(result.returncode, 0, "missing SBOM must fail")
        self.assertIn("sbom", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
