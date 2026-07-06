import unittest
from monitor.baseline import Baseline


class BaselineTests(unittest.TestCase):
    def test_warmup_required(self):
        b = Baseline(history_size=100, warmup=5, metrics=["x"])
        self.assertFalse(b.is_warm)
        for _ in range(4):
            b.update({"x": 10.0})
        self.assertFalse(b.is_warm)
        b.update({"x": 10.0})
        self.assertTrue(b.is_warm)

    def test_zscore_zero_when_no_variance(self):
        b = Baseline(history_size=100, warmup=2, metrics=["x"])
        for _ in range(20):
            b.update({"x": 5.0})
        self.assertEqual(b.zscore("x", 5.0), 0.0)

    def test_zscore_detects_outlier(self):
        b = Baseline(history_size=100, warmup=2, metrics=["x"])
        for v in [10, 11, 9, 10, 12, 9, 10, 11, 10, 9, 10, 11]:
            b.update({"x": float(v)})
        z = b.zscore("x", 50.0)
        self.assertIsNotNone(z)
        self.assertGreater(z, 5.0)


if __name__ == "__main__":
    unittest.main()
