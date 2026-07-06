"""Aggregate raw flows into per-window feature vectors.

A "window" is a fixed slice of wall-clock time (default 1s, set in config).
For each window we summarize traffic into the metrics the baseline learner
and signature detectors consume.
"""
from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set

from .flow import Flow


@dataclass
class Window:
    start_ts: float
    end_ts: float
    flows: int = 0
    packets: int = 0          # we treat each Flow as 1 packet for simplicity
    bytes: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    src_ips: Set[str] = field(default_factory=set)
    dst_ips: Set[str] = field(default_factory=set)
    src_ports: Set[int] = field(default_factory=set)
    dst_ports: Set[int] = field(default_factory=set)
    bytes_by_src: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    bytes_by_dst: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    bytes_by_dst_port: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    bytes_by_proto: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    # per-src dst_ports (for port-scan signature)
    dst_ports_by_src: Dict[str, Set[int]] = field(
        default_factory=lambda: defaultdict(set)
    )
    # per-dst src_ips (for DDoS signature)
    src_ips_by_dst: Dict[str, Set[str]] = field(
        default_factory=lambda: defaultdict(set)
    )
    # per (src,dst) bytes (for exfil signature)
    bytes_by_src_dst: Dict[tuple, int] = field(
        default_factory=lambda: defaultdict(int)
    )

    @property
    def unique_src_ips(self) -> int: return len(self.src_ips)
    @property
    def unique_dst_ips(self) -> int: return len(self.dst_ips)
    @property
    def unique_src_ports(self) -> int: return len(self.src_ports)
    @property
    def unique_dst_ports(self) -> int: return len(self.dst_ports)

    def add(self, f: Flow) -> None:
        self.flows += 1
        self.packets += 1
        self.bytes += f.length
        if f.protocol == "TCP":
            self.tcp_packets += 1
        elif f.protocol == "UDP":
            self.udp_packets += 1
        elif f.protocol == "ICMP":
            self.icmp_packets += 1
        self.src_ips.add(f.src_ip)
        self.dst_ips.add(f.dst_ip)
        if f.src_port:
            self.src_ports.add(f.src_port)
        if f.dst_port:
            self.dst_ports.add(f.dst_port)
        self.bytes_by_src[f.src_ip] += f.length
        self.bytes_by_dst[f.dst_ip] += f.length
        if f.dst_port:
            self.bytes_by_dst_port[f.dst_port] += f.length
        self.bytes_by_proto[f.protocol] += f.length
        if f.dst_port:
            self.dst_ports_by_src[f.src_ip].add(f.dst_port)
        self.src_ips_by_dst[f.dst_ip].add(f.src_ip)
        self.bytes_by_src_dst[(f.src_ip, f.dst_ip)] += f.length

    def metrics(self) -> Dict[str, float]:
        """The numeric feature vector consumed by the statistical baseline."""
        return {
            "packets": float(self.packets),
            "bytes": float(self.bytes),
            "tcp_packets": float(self.tcp_packets),
            "udp_packets": float(self.udp_packets),
            "icmp_packets": float(self.icmp_packets),
            "unique_src_ips": float(self.unique_src_ips),
            "unique_dst_ips": float(self.unique_dst_ips),
            "unique_src_ports": float(self.unique_src_ports),
            "unique_dst_ports": float(self.unique_dst_ports),
        }

    def top_talkers(self, n: int = 10) -> List[Dict]:
        items = sorted(self.bytes_by_src.items(), key=lambda x: -x[1])[:n]
        return [{"ip": ip, "bytes": b} for ip, b in items]

    def top_dst_ports(self, n: int = 10) -> List[Dict]:
        items = sorted(self.bytes_by_dst_port.items(), key=lambda x: -x[1])[:n]
        return [{"port": p, "bytes": b} for p, b in items]

    def proto_breakdown(self) -> Dict[str, int]:
        return {
            "TCP": self.tcp_packets,
            "UDP": self.udp_packets,
            "ICMP": self.icmp_packets,
        }


class WindowAggregator:
    """Buckets a stream of Flow records into fixed-width Windows.

    Call .ingest(flows) repeatedly; .drain_completed(now) yields any windows
    that have ended before `now` and removes them from the open set.
    """

    def __init__(self, window_seconds: float):
        self.window_seconds = float(window_seconds)
        self._open: Dict[float, Window] = {}

    def _bucket_key(self, ts: float) -> float:
        return float(int(ts / self.window_seconds) * self.window_seconds)

    def ingest(self, flows: List[Flow]) -> None:
        for f in flows:
            key = self._bucket_key(f.ts)
            w = self._open.get(key)
            if w is None:
                w = Window(start_ts=key, end_ts=key + self.window_seconds)
                self._open[key] = w
            w.add(f)

    def drain_completed(self, now: float) -> List[Window]:
        cutoff = self._bucket_key(now)  # window currently in progress
        done: List[Window] = []
        for k in sorted(self._open.keys()):
            if k < cutoff:
                done.append(self._open.pop(k))
        return done

    def force_flush(self) -> List[Window]:
        out = list(self._open.values())
        self._open.clear()
        out.sort(key=lambda w: w.start_ts)
        return out
