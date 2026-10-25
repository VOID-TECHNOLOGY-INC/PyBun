import contextlib
import hashlib
import io
import os
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from pybun import bootstrap


class DetectTargetTests(unittest.TestCase):
    def test_macos_arm64(self):
        target = bootstrap.detect_target(system="Darwin", machine="arm64")
        self.assertEqual(target, "aarch64-apple-darwin")

    def test_linux_musl(self):
        target = bootstrap.detect_target(system="Linux", machine="x86_64", is_musl=True)
        self.assertEqual(target, "x86_64-unknown-linux-musl")

    def test_linux_gnu(self):
        target = bootstrap.detect_target(system="Linux", machine="x86_64", is_musl=False)
        self.assertEqual(target, "x86_64-unknown-linux-gnu")

    def test_linux_aarch64_gnu(self):
        target = bootstrap.detect_target(system="Linux", machine="aarch64", is_musl=False)
        self.assertEqual(target, "aarch64-unknown-linux-gnu")

    def test_linux_aarch64_musl_fails_fast(self):
        with self.assertRaises(bootstrap.BootstrapError) as caught:
            bootstrap.detect_target(system="Linux", machine="aarch64", is_musl=True)
        self.assertIn("aarch64 musl", str(caught.exception))

    def test_explicit_target_still_overrides_aarch64_musl(self):
        previous = os.environ.get("PYBUN_PYPI_TARGET")
        os.environ["PYBUN_PYPI_TARGET"] = "aarch64-unknown-linux-musl"
        try:
            target = bootstrap.detect_target(system="Linux", machine="aarch64", is_musl=True)
        finally:
            if previous is None:
                os.environ.pop("PYBUN_PYPI_TARGET", None)
            else:
                os.environ["PYBUN_PYPI_TARGET"] = previous
        self.assertEqual(target, "aarch64-unknown-linux-musl")


class SelectAssetTests(unittest.TestCase):
    def test_select_asset_by_target(self):
        manifest = {
            "assets": [
                {
                    "name": "pybun-x86_64-unknown-linux-gnu.tar.gz",
                    "target": "x86_64-unknown-linux-gnu",
                    "url": "https://example.com/pybun.tar.gz",
                    "sha256": "deadbeef",
                }
            ]
        }
        asset = bootstrap.select_asset(manifest, "x86_64-unknown-linux-gnu")
        self.assertEqual(asset["name"], "pybun-x86_64-unknown-linux-gnu.tar.gz")

    def test_select_asset_missing_target_raises(self):
        manifest = {"assets": []}
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.select_asset(manifest, "aarch64-apple-darwin")


class FallbackSelectionTests(unittest.TestCase):
    def setUp(self):
        # Ensure clean env overrides
        self._env = dict(os.environ)
        for k in [
            "PYBUN_PYPI_PREFER_MUSL",
            "PYBUN_PYPI_TARGET",
            "PYBUN_PYPI_NO_FALLBACK",
        ]:
            os.environ.pop(k, None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)

    def test_prefer_musl_overrides_gnu(self):
        os.environ["PYBUN_PYPI_PREFER_MUSL"] = "1"
        manifest = {
            "assets": [
                {"name": "gnu.tgz", "target": "x86_64-unknown-linux-gnu", "url": "file:///gnu", "sha256": "dead"},
                {"name": "musl.tgz", "target": "x86_64-unknown-linux-musl", "url": "file:///musl", "sha256": "beef"},
            ]
        }
        asset = bootstrap.select_asset_with_fallback(manifest, "x86_64-unknown-linux-gnu")
        self.assertEqual(asset["target"], "x86_64-unknown-linux-musl")

    def test_glibc_too_old_falls_back_to_musl(self):
        # Force local glibc to appear older than required
        orig_detect = bootstrap.detect_glibc_version

        def fake_detect():
            return "2.28"

        bootstrap.detect_glibc_version = fake_detect
        try:
            manifest = {
                "assets": [
                    {
                        "name": "gnu.tgz",
                        "target": "x86_64-unknown-linux-gnu",
                        "url": "file:///gnu",
                        "sha256": "dead",
                        "compat": {"libc": "glibc", "min_glibc": "2.31"},
                    },
                    {
                        "name": "musl.tgz",
                        "target": "x86_64-unknown-linux-musl",
                        "url": "file:///musl",
                        "sha256": "beef",
                        "compat": {"libc": "musl"},
                    },
                ]
            }
            asset = bootstrap.select_asset_with_fallback(manifest, "x86_64-unknown-linux-gnu")
            self.assertEqual(asset["target"], "x86_64-unknown-linux-musl")
        finally:
            bootstrap.detect_glibc_version = orig_detect


    def test_glibc_234_fallback_boundary(self):
        manifest = {"assets": [
            {"target": "x86_64-unknown-linux-gnu", "compat": {"min_glibc": "2.34"}},
            {"target": "x86_64-unknown-linux-musl"},
        ]}
        with patch.dict(os.environ, {"PYBUN_PYPI_PREFER_MUSL": "0", "PYBUN_PYPI_NO_FALLBACK": "0"}):
            for version, expected in [("2.31", "musl"), ("2.33", "musl"),
                                      ("2.34", "gnu"), ("2.35", "gnu")]:
                with self.subTest(version=version), patch.object(bootstrap, "detect_glibc_version", return_value=version):
                    asset = bootstrap.select_asset_with_fallback(manifest, "x86_64-unknown-linux-gnu")
                    self.assertTrue(asset["target"].endswith(expected), asset)


class VerifyChecksumTests(unittest.TestCase):
    def test_rejects_placeholder(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"data")
            f.flush()
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap._verify_checksum(f.name, "placeholder")
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap._verify_checksum(f.name, "sha256:placeholder")

    def test_rejects_missing_or_empty(self):
        with tempfile.NamedTemporaryFile() as f:
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap._verify_checksum(f.name, None)
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap._verify_checksum(f.name, "")

    def test_accepts_matching_checksum(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"hello world")
            path = f.name
        try:
            digest = hashlib.sha256(b"hello world").hexdigest()
            bootstrap._verify_checksum(path, digest)
            bootstrap._verify_checksum(path, f"sha256:{digest}")
        finally:
            os.remove(path)

    def test_rejects_non_string_checksum(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"data")
            f.flush()
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap._verify_checksum(f.name, 12345)  # type: ignore[arg-type]
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap._verify_checksum(f.name, ["deadbeef"])  # type: ignore[arg-type]

    def test_rejects_mismatch(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"hello world")
            path = f.name
        try:
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap._verify_checksum(path, "deadbeef" * 8)
        finally:
            os.remove(path)


class DownloadUrlSchemeTests(unittest.TestCase):
    def test_rejects_plain_http(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = os.path.join(tmp, "out")
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap._download_url("http://example.com/pybun.tar.gz", dest)
            self.assertFalse(os.path.exists(dest))

    def test_allows_file_scheme(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "src")
            with open(src, "wb") as f:
                f.write(b"payload")
            dest = os.path.join(tmp, "dest")
            bootstrap._download_url(f"file://{src}", dest)
            with open(dest, "rb") as f:
                self.assertEqual(f.read(), b"payload")


class LoadManifestSchemeTests(unittest.TestCase):
    def test_rejects_plain_http(self):
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_manifest("http://example.com/pybun-release.json")


class NoVerifyWarningTests(unittest.TestCase):
    def setUp(self):
        self._env = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)

    def test_prints_warning_when_verification_disabled(self):
        os.environ["PYBUN_PYPI_NO_VERIFY"] = "1"
        os.environ["PYBUN_PYPI_TARGET"] = "x86_64-unknown-linux-gnu"
        os.environ["PYBUN_PYPI_MANIFEST"] = "/nonexistent/pybun-release.json"
        os.environ.pop("PYBUN_PYPI_OFFLINE", None)
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["PYBUN_HOME"] = tmp
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.ensure_binary()
            self.assertIn("PYBUN_PYPI_NO_VERIFY", stderr.getvalue())


class SafeExtractTarTests(unittest.TestCase):
    def test_rejects_path_traversal_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = os.path.join(tmp, "evil.tar")
            dest = os.path.join(tmp, "dest")
            os.makedirs(dest)
            with tarfile.open(archive_path, "w") as tar:
                info = tarfile.TarInfo(name="../outside.txt")
                info.size = 0
                tar.addfile(info)
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap._safe_extract_tar(archive_path, dest)

    def test_rejects_symlink_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = os.path.join(tmp, "evil.tar")
            dest = os.path.join(tmp, "dest")
            os.makedirs(dest)
            with tarfile.open(archive_path, "w") as tar:
                info = tarfile.TarInfo(name="escape")
                info.type = tarfile.SYMTYPE
                info.linkname = "../../etc"
                tar.addfile(info)
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap._safe_extract_tar(archive_path, dest)

    def test_rejects_hardlink_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = os.path.join(tmp, "evil.tar")
            dest = os.path.join(tmp, "dest")
            os.makedirs(dest)
            with tarfile.open(archive_path, "w") as tar:
                info = tarfile.TarInfo(name="escape")
                info.type = tarfile.LNKTYPE
                info.linkname = "../../etc/passwd"
                tar.addfile(info)
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap._safe_extract_tar(archive_path, dest)

    def test_allows_legitimate_nested_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = os.path.join(tmp, "ok.tar")
            dest = os.path.join(tmp, "dest")
            os.makedirs(dest)
            with tarfile.open(archive_path, "w") as tar:
                # A symlink nested one level deep pointing to a sibling
                # directory within dest via ".." must not be rejected, since
                # the OS resolves it relative to "bin/", not to dest itself.
                info = tarfile.TarInfo(name="bin/lib")
                info.type = tarfile.SYMTYPE
                info.linkname = "../shared/lib"
                tar.addfile(info)
            bootstrap._safe_extract_tar(archive_path, dest)
            link_path = os.path.join(dest, "bin", "lib")
            self.assertTrue(os.path.islink(link_path))
            self.assertEqual(os.readlink(link_path), "../shared/lib")

    def test_does_not_apply_the_data_filter(self):
        from unittest import mock

        with tempfile.TemporaryDirectory() as tmp:
            archive_path = os.path.join(tmp, "ok.tar")
            dest = os.path.join(tmp, "dest")
            os.makedirs(dest)
            with tarfile.open(archive_path, "w") as tar:
                info = tarfile.TarInfo(name="bin/lib")
                info.type = tarfile.SYMTYPE
                info.linkname = "../shared/lib"
                tar.addfile(info)
            with mock.patch.object(
                tarfile,
                "data_filter",
                side_effect=AssertionError("data filter must not be used"),
                create=True,
            ):
                bootstrap._safe_extract_tar(archive_path, dest)
            self.assertTrue(os.path.islink(os.path.join(dest, "bin", "lib")))

    def test_extracts_valid_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = os.path.join(tmp, "ok.tar")
            dest = os.path.join(tmp, "dest")
            os.makedirs(dest)
            payload_path = os.path.join(tmp, "payload.txt")
            with open(payload_path, "w", encoding="utf-8") as f:
                f.write("hello")
            with tarfile.open(archive_path, "w") as tar:
                tar.add(payload_path, arcname="payload.txt")
            bootstrap._safe_extract_tar(archive_path, dest)
            with open(os.path.join(dest, "payload.txt"), encoding="utf-8") as f:
                self.assertEqual(f.read(), "hello")


class MinisignPrerequisiteTests(unittest.TestCase):
    def test_missing_minisign_error_lists_install_commands(self):
        from unittest import mock

        signature = {
            "type": "minisign",
            "value": "untrusted comment: signature\nabc",
            "public_key": "untrusted comment: public key\ndef",
        }
        with mock.patch.object(bootstrap.shutil, "which", return_value=None):
            with self.assertRaises(bootstrap.BootstrapError) as caught:
                bootstrap._verify_signature("archive.tar.gz", signature)
        message = str(caught.exception)
        for command in ("brew install minisign", "apt-get install minisign", "apk add minisign"):
            self.assertIn(command, message)
        self.assertIn("insecure", message)
        self.assertLess(
            message.index("brew install minisign"),
            message.index("PYBUN_PYPI_NO_VERIFY"),
        )


if __name__ == "__main__":
    unittest.main()


class TrustedSignatureKeyTests(unittest.TestCase):
    def test_signature_uses_the_pinned_key_not_the_manifest_key(self):
        from unittest import mock
        from types import SimpleNamespace

        captured = {}

        def fake_run(command, **kwargs):
            pub_path = command[command.index("-p") + 1]
            with open(pub_path, encoding="utf-8") as handle:
                captured["public_key"] = handle.read()
            return SimpleNamespace(returncode=0, stderr="")

        with mock.patch.object(
            bootstrap, "TRUSTED_MINISIGN_PUBLIC_KEY", "trusted-key-line"
        ), mock.patch.object(
            bootstrap.shutil, "which", return_value="/usr/bin/minisign"
        ), mock.patch.object(
            bootstrap.subprocess, "run", side_effect=fake_run
        ):
            bootstrap._verify_signature(
                "archive.tar.gz",
                {
                    "type": "minisign",
                    "value": "signature",
                    "public_key": "attacker-controlled-key",
                },
            )
        self.assertIn("trusted-key-line", captured["public_key"])
        self.assertNotIn("attacker-controlled-key", captured["public_key"])
