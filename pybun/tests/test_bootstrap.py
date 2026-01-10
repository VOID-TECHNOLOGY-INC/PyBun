import os
import unittest

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


if __name__ == "__main__":
    unittest.main()
