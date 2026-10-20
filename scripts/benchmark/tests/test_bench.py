import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import bench


class TestTrimSamples(unittest.TestCase):
    def test_trim_samples_drops_outliers(self) -> None:
        samples = [1.0, 2.0, 100.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0]
        trimmed = bench.trim_samples(samples, trim_ratio=0.1)
        self.assertEqual(trimmed, [2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0])

    def test_trim_samples_noop_when_ratio_zero(self) -> None:
        samples = [3.0, 1.0, 2.0]
        trimmed = bench.trim_samples(samples, trim_ratio=0.0)
        self.assertEqual(trimmed, samples)


class TestComputeStats(unittest.TestCase):
    def test_compute_stats_uses_trimmed_samples(self) -> None:
        samples = [1.0, 2.0, 100.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0]
        stats = bench.compute_stats(samples, trim_ratio=0.1)
        self.assertAlmostEqual(stats[0], 5.5, places=2)
        self.assertEqual(stats[4], 8)


class TestFindToolRelativePath(unittest.TestCase):
    """find_tool must resolve relative paths against _base_dir, not cwd."""

    def test_relative_path_resolved_against_base_dir(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            bin_dir = tmp / "bin"
            bin_dir.mkdir()
            fake_pybun = tmp / "bin" / "pybun"
            fake_pybun.write_text("#!/bin/sh\nexit 0")
            fake_pybun.chmod(0o755)

            config = {
                "_base_dir": str(tmp),
                "paths": {"pybun": "bin/pybun"},
            }

            original_cwd = os.getcwd()
            try:
                os.chdir("/tmp")
                result = bench.find_tool("pybun", config)
            finally:
                os.chdir(original_cwd)

            self.assertEqual(result, str(fake_pybun))

    def test_relative_path_without_base_dir_falls_through_to_which(self) -> None:
        """Without _base_dir, a relative path that doesn't exist returns PATH lookup (None)."""
        config = {
            "paths": {"nonexistent_tool_xyz": "../../target/release/nonexistent_xyz"},
        }
        result = bench.find_tool("nonexistent_tool_xyz", config)
        self.assertIsNone(result)

    def test_absolute_path_still_works(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            fake_pybun = tmp / "pybun"
            fake_pybun.write_text("#!/bin/sh\nexit 0")
            fake_pybun.chmod(0o755)

            config = {
                "_base_dir": "/some/other/dir",
                "paths": {"pybun": str(fake_pybun)},
            }
            result = bench.find_tool("pybun", config)
            self.assertEqual(result, str(fake_pybun))


class TestMeasurementFailures(unittest.TestCase):
    def test_stdout_and_stderr_survive_nonzero_exit(self):
        result = bench.measure_command(
            [sys.executable, "-c", "import sys; print('out-reason'); print('err-reason', file=sys.stderr); sys.exit(7)"],
            warmup=0, iterations=1,
        )
        self.assertFalse(result.success)
        self.assertIn("exit code 7", result.error)
        self.assertIn("out-reason", result.error)
        self.assertIn("err-reason", result.error)

    def test_warmup_failure_is_not_hidden_by_successful_samples(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            code = "from pathlib import Path; import sys; p=Path('seen'); seen=p.exists(); p.touch(); sys.exit(0 if seen else 8)"
            result = bench.measure_command([sys.executable, "-c", code], warmup=1, iterations=1, cwd=tmp)
        self.assertFalse(result.success)
        self.assertIn("warmup", result.error)
        self.assertIn("exit code 8", result.error)

    def test_failure_diagnostics_are_bounded(self):
        result = bench.measure_command(
            [sys.executable, "-c", "import sys; print('x'*10000); print('y'*10000,file=sys.stderr);sys.exit(1)"],
            warmup=0, iterations=1,
        )
        self.assertFalse(result.success)
        self.assertLess(len(result.error), 1200)

    def test_launch_failure_and_timeout_remain_failures(self):
        missing = bench.measure_command(["/nonexistent/pybun-benchmark-test"], warmup=0, iterations=1)
        self.assertFalse(missing.success)
        self.assertTrue(missing.error)
        timed = bench.measure_command(
            [sys.executable, "-c", "import time;print('before-timeout',flush=True);time.sleep(10)"],
            warmup=0, iterations=1, timeout=0.1,
        )
        self.assertFalse(timed.success)
        self.assertIn("Timeout", timed.error)
        self.assertIn("before-timeout", timed.error)

    def test_failed_pybun_and_reference_results_do_not_win(self):
        for success, metadata in [(False, {}), (True, {"reference_only": True})]:
            with self.subTest(success=success, metadata=metadata):
                summary = bench.generate_summary([
                    bench.BenchResult("C1", "pybun", 1.0, success=success, metadata=metadata),
                    bench.BenchResult("C1", "uv", 10.0),
                ])
                self.assertEqual(summary["pybun_wins"], 0)
                self.assertEqual(summary["pybun_losses"], 0)


if __name__ == "__main__":
    unittest.main()
