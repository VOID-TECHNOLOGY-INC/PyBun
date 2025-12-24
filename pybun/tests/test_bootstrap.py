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


if __name__ == "__main__":
    unittest.main()
