"""Detector tests — verify the three signature detectors fire on
synthetic attack traffic and stay quiet on benign baselines."""
import unittest
from monitor.baseline import Baseline
from monitor.config import Config
from monitor.detector import (CompositeDetector, DDoSDetector,
                              ExfilDetector, PortScanDetector,
                              StatisticalDetector)
from monitor.features import WindowAggregator
from monitor.flow import Flow


def _agg(flows, ws=1.0):
    a = WindowAggregator(window_seconds=ws)
    a.ingest(flows)
    last_ts = max(f.ts for f in flows) + ws + 0.1
    return a.drain_completed(now=last_ts)


class PortScanTests(unittest.TestCase):
    def test_fires_on_many_ports_one_src(self):
        cfg = Config()
        cfg.portscan_min_ports = 20
        det = PortScanDetector(cfg)
        flows = [
            Flow(ts=10 + i*0.01, src_ip="9.9.9.9", dst_ip="10.0.0.5",
                 src_port=12345, dst_port=p, protocol="TCP", length=60)
            for i, p in enumerate(range(1000, 1050))
        ]
        windows = _agg(flows)
        out = []
        for w in windows:
            out.extend(det.detect(w))
        self.assertTrue(any(d.type == "port-scan" for d in out))

    def test_quiet_on_normal_traffic(self):
        cfg = Config()
        det = PortScanDetector(cfg)
        flows = [
            Flow(ts=10 + i*0.1, src_ip="10.0.0.1", dst_ip="8.8.8.8",
                 src_port=12345, dst_port=443, protocol="TCP", length=200)
            for i in range(50)
        ]
        windows = _agg(flows)
        out = []
        for w in windows:
            out.extend(det.detect(w))
        self.assertFalse(any(d.type == "port-scan" for d in out))


class DDoSTests(unittest.TestCase):
    def test_fires_when_many_srcs_one_dst(self):
        cfg = Config()
        cfg.ddos_min_sources = 30
        cfg.ddos_min_pps = 30
        det = DDoSDetector(cfg)
        flows = []
        for i in range(60):
            flows.append(Flow(ts=10 + i*0.01,
                              src_ip=f"198.51.100.{i+1}",
                              dst_ip="10.0.0.7",
                              src_port=10000 + i, dst_port=80,
                              protocol="TCP", length=64))
        windows = _agg(flows)
        out = []
        for w in windows:
            out.extend(det.detect(w))
        self.assertTrue(any(d.type == "ddos" for d in out))


class ExfilTests(unittest.TestCase):
    def test_fires_on_large_internal_to_external(self):
        cfg = Config()
        cfg.exfil_bytes_abs = 1_000_000  # 1 MB threshold
        baseline = Baseline(history_size=10, warmup=2, metrics=["bytes"])
        det = ExfilDetector(cfg, baseline)
        flows = [
            Flow(ts=10 + i*0.01, src_ip="10.0.0.42",
                 dst_ip="185.199.10.20",
                 src_port=10000 + i, dst_port=443,
                 protocol="TCP", length=20000)
            for i in range(120)
        ]
        windows = _agg(flows)
        out = []
        for w in windows:
            out.extend(det.detect(w))
        self.assertTrue(any(d.type == "exfil" for d in out))


class StatisticalTests(unittest.TestCase):
    def test_fires_on_traffic_spike(self):
        baseline = Baseline(history_size=50, warmup=5, metrics=["packets"])
        # train on quiet baseline
        for _ in range(20):
            baseline.update({"packets": 50.0 + (1 if _ % 2 else -1)})
        det = StatisticalDetector(baseline, threshold=3.0)
        from monitor.features import Window
        w = Window(start_ts=0, end_ts=1)
        # synthesize a spike of 500 packets in this window
        for _ in range(500):
            w.add(Flow(0.1, "10.0.0.1", "8.8.8.8", 1, 443, "TCP", 100))
        out = det.detect(w)
        self.assertTrue(any(d.type == "z-score" for d in out))


if __name__ == "__main__":
    unittest.main()
