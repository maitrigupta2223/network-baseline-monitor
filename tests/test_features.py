import unittest
from monitor.flow import Flow
from monitor.features import WindowAggregator


class WindowTests(unittest.TestCase):
    def test_buckets_by_time(self):
        agg = WindowAggregator(window_seconds=1.0)
        agg.ingest([
            Flow(100.1, "10.0.0.1", "8.8.8.8", 33333, 443, "TCP", 200),
            Flow(100.5, "10.0.0.2", "8.8.8.8", 44444, 53, "UDP", 100),
            Flow(101.2, "10.0.0.3", "8.8.8.8", 55555, 80, "TCP", 300),
        ])
        done = agg.drain_completed(now=102.5)
        self.assertEqual(len(done), 2)
        self.assertEqual(done[0].packets, 2)
        self.assertEqual(done[1].packets, 1)

    def test_metrics(self):
        agg = WindowAggregator(window_seconds=1.0)
        agg.ingest([
            Flow(50.0, "10.0.0.1", "8.8.8.8", 1000, 443, "TCP", 1000),
            Flow(50.5, "10.0.0.2", "1.1.1.1", 2000, 80, "TCP", 500),
        ])
        done = agg.drain_completed(now=52.0)
        m = done[0].metrics()
        self.assertEqual(m["packets"], 2)
        self.assertEqual(m["bytes"], 1500)
        self.assertEqual(m["unique_src_ips"], 2)
        self.assertEqual(m["unique_dst_ports"], 2)


if __name__ == "__main__":
    unittest.main()
