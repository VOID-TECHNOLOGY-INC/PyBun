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


if __name__ == "__main__":
    unittest.main()
