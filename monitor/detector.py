"""Anomaly detectors.

Three layers run on every completed window:

  1. Statistical (z-score) — flags any monitored metric whose value deviates
     from the learned baseline by > Z standard deviations.

  2. Signature — recognises specific attack shapes:
       - Port scan (one src probing many distinct dst_ports)
       - DDoS (many distinct srcs hammering one dst at high pps)
       - Data exfiltration (large outbound bytes from internal -> external)

  3. (Implicit) absolute thresholds inside signatures act as floors so the
     system raises sensible alerts even before warmup is complete.

Each detector returns a list of `Detection` objects. The AlertManager owns
deduping and persistence.
"""
from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional
from collections import deque

from .baseline import Baseline
from .config import Config
from .features import Window
from .utils import is_internal


SEVERITY_INFO = "info"
SEVERITY_WARN = "warning"
SEVERITY_CRIT = "critical"


@dataclass
class Detection:
    type: str                 # "z-score" | "port-scan" | "ddos" | "exfil"
    severity: str             # info | warning | critical
    title: str
    description: str
    key: str                  # used for alert dedup
    evidence: Dict = field(default_factory=dict)
    ts: float = 0.0


class StatisticalDetector:
    """Flags z-score outliers across the configured metrics."""

    def __init__(self, baseline: Baseline, threshold: float):
        self.baseline = baseline
        self.threshold = threshold

    def detect(self, window: Window) -> List[Detection]:
        if not self.baseline.is_warm:
            return []
        # collect every metric that's outside the threshold, sorted by
        # |z| so the most surprising one is reported first.
        spikes = []
        metrics = window.metrics()
        for m, v in metrics.items():
            z = self.baseline.zscore(m, v)
            if z is None or abs(z) <= self.threshold:
                continue
            stat = self.baseline.stat(m)
            spikes.append((abs(z), m, z, v, stat.mean, stat.stdev))
        if not spikes:
            return []
        # one alert per window, even if many metrics deviated — otherwise a
        # single attack carpets the alerts feed (DDoS spikes packets,
        # tcp_packets, bytes, unique_src_ips all at once).
        spikes.sort(reverse=True)
        az, m, z, v, mean, stdev = spikes[0]
        sev = SEVERITY_CRIT if az > self.threshold * 1.5 else SEVERITY_WARN
        also = [s[1] for s in spikes[1:4]]
        desc = (f"{m} = {v:.1f} is {z:+.2f}σ from baseline "
                f"(mean={mean:.1f}, stdev={stdev:.1f})")
        if also:
            desc += f"; also abnormal: {', '.join(also)}"
        return [Detection(
            type="z-score",
            severity=sev,
            title="Statistical anomaly: traffic deviation",
            description=desc,
            key="zscore:any",
            evidence={"worst_metric": m, "value": v, "z": z,
                      "mean": mean, "stdev": stdev,
                      "all_spikes": [{"metric": s[1], "z": s[2]} for s in spikes]},
            ts=window.end_ts,
        )]


class PortScanDetector:
    """Detects one source probing many distinct destination ports."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        # rolling per-src dst_port set across recent windows
        self._buf: Deque[Window] = deque()

    def detect(self, window: Window) -> List[Detection]:
        # maintain a window of size N seconds
        self._buf.append(window)
        cutoff = window.end_ts - self.cfg.portscan_window_seconds
        while self._buf and self._buf[0].end_ts < cutoff:
            self._buf.popleft()

        # union dst_ports per src across the buffer
        union: Dict[str, set] = defaultdict(set)
        union_dsts: Dict[str, set] = defaultdict(set)
        for w in self._buf:
            for src, ports in w.dst_ports_by_src.items():
                union[src].update(ports)
                # also collect distinct dsts the src talked to
                # (port scans usually focus one dst)
                pass
            for (src, _dst), _bytes in w.bytes_by_src_dst.items():
                pass  # dsts captured below

        # pull dsts per src directly from raw maps
        for w in self._buf:
            for (src, dst), _b in w.bytes_by_src_dst.items():
                union_dsts[src].add(dst)

        out: List[Detection] = []
        for src, ports in union.items():
            if len(ports) >= self.cfg.portscan_min_ports:
                dsts = union_dsts.get(src, set())
                # Skip "scans" that look like a normal client talking to many
                # services across many destinations (low ports/dst ratio).
                if len(dsts) > 0 and (len(ports) / max(1, len(dsts))) < 5:
                    # broad fan-out — could be legit; skip unless extreme
                    if len(ports) < self.cfg.portscan_min_ports * 3:
                        continue
                out.append(Detection(
                    type="port-scan",
                    severity=SEVERITY_CRIT,
                    title="Port scan detected",
                    description=(
                        f"{src} probed {len(ports)} distinct ports across "
                        f"{len(dsts)} target(s) in the last "
                        f"{self.cfg.portscan_window_seconds:.0f}s"
                    ),
                    key=f"portscan:{src}",
                    evidence={
                        "src": src,
                        "distinct_ports": len(ports),
                        "distinct_targets": len(dsts),
                        "sample_ports": sorted(list(ports))[:30],
                        "targets": sorted(list(dsts))[:10],
                    },
                    ts=window.end_ts,
                ))
        return out


class DDoSDetector:
    """Detects many distinct sources hammering one destination."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._buf: Deque[Window] = deque()

    def detect(self, window: Window) -> List[Detection]:
        self._buf.append(window)
        cutoff = window.end_ts - self.cfg.ddos_window_seconds
        while self._buf and self._buf[0].end_ts < cutoff:
            self._buf.popleft()

        union_srcs: Dict[str, set] = defaultdict(set)
        pkts_to_dst: Dict[str, int] = defaultdict(int)
        for w in self._buf:
            for dst, srcs in w.src_ips_by_dst.items():
                union_srcs[dst].update(srcs)
            for dst, b in w.bytes_by_dst.items():
                pkts_to_dst[dst] += b

        # pps proxy: total bytes / window. We use total packets too.
        out: List[Detection] = []
        # also count packets to dst
        pkts_count: Dict[str, int] = defaultdict(int)
        for w in self._buf:
            for (src, dst), _b in w.bytes_by_src_dst.items():
                pkts_count[dst] += 1  # one Flow == one packet by convention

        for dst, srcs in union_srcs.items():
            if len(srcs) >= self.cfg.ddos_min_sources and \
               pkts_count.get(dst, 0) >= self.cfg.ddos_min_pps:
                out.append(Detection(
                    type="ddos",
                    severity=SEVERITY_CRIT,
                    title="DDoS pattern detected",
                    description=(
                        f"{dst} received traffic from {len(srcs)} distinct "
                        f"sources ({pkts_count[dst]} packets) in the last "
                        f"{self.cfg.ddos_window_seconds:.0f}s"
                    ),
                    key=f"ddos:{dst}",
                    evidence={
                        "target": dst,
                        "distinct_sources": len(srcs),
                        "packets": pkts_count[dst],
                        "sample_sources": sorted(list(srcs))[:20],
                    },
                    ts=window.end_ts,
                ))
        return out


class ExfilDetector:
    """Detects unusually large outbound transfers from internal hosts."""

    def __init__(self, cfg: Config, baseline: Baseline):
        self.cfg = cfg
        self.baseline = baseline
        self._buf: Deque[Window] = deque()

    def detect(self, window: Window) -> List[Detection]:
        self._buf.append(window)
        cutoff = window.end_ts - self.cfg.exfil_window_seconds
        while self._buf and self._buf[0].end_ts < cutoff:
            self._buf.popleft()

        # sum bytes per (src, dst) where src is internal & dst is external
        per_pair: Dict[tuple, int] = defaultdict(int)
        for w in self._buf:
            for (src, dst), b in w.bytes_by_src_dst.items():
                if is_internal(src, self.cfg.internal_cidrs) and \
                   not is_internal(dst, self.cfg.internal_cidrs):
                    per_pair[(src, dst)] += b

        # baseline mean of total bytes per window (rough reference)
        bstat = self.baseline.stat("bytes")
        ref_mean = bstat.mean if bstat else 0.0

        out: List[Detection] = []
        for (src, dst), b in per_pair.items():
            if b >= self.cfg.exfil_bytes_abs or (
                ref_mean > 0 and b >= self.cfg.exfil_bytes_ratio * ref_mean
            ):
                out.append(Detection(
                    type="exfil",
                    severity=SEVERITY_CRIT,
                    title="Possible data exfiltration",
                    description=(
                        f"{src} sent {b/1024/1024:.2f} MB to external host "
                        f"{dst} in the last "
                        f"{self.cfg.exfil_window_seconds:.0f}s"
                    ),
                    key=f"exfil:{src}->{dst}",
                    evidence={
                        "internal_src": src,
                        "external_dst": dst,
                        "bytes": b,
                        "baseline_window_bytes_mean": ref_mean,
                    },
                    ts=window.end_ts,
                ))
        return out


class CompositeDetector:
    """Bundles all detectors and decides whether the window is 'clean' for
    the baseline."""

    def __init__(self, cfg: Config, baseline: Baseline):
        self.cfg = cfg
        self.baseline = baseline
        self.stat = StatisticalDetector(baseline, cfg.z_threshold)
        self.scan = PortScanDetector(cfg)
        self.ddos = DDoSDetector(cfg)
        self.exfil = ExfilDetector(cfg, baseline)

    def detect(self, window: Window) -> List[Detection]:
        out: List[Detection] = []
        out.extend(self.stat.detect(window))
        out.extend(self.scan.detect(window))
        out.extend(self.ddos.detect(window))
        out.extend(self.exfil.detect(window))
        return out
