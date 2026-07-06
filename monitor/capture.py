"""Live packet capture using scapy.

This is the "real" data source. It requires root/admin (raw socket access)
and the optional `scapy` dependency. The simulator in simulator.py provides
the same Flow stream without those requirements for demos and CI.

Usage:
    cap = LiveCapture(iface="en0")
    cap.start()
    flows = cap.pop_batch()
"""
from __future__ import annotations
import threading
import time
from typing import List, Optional

from .flow import Flow


class LiveCapture:
    def __init__(self, iface: Optional[str] = None, bpf_filter: str = "ip"):
        self.iface = iface
        self.bpf_filter = bpf_filter
        self._lock = threading.Lock()
        self._buffer: List[Flow] = []
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._sniffer = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        try:
            from scapy.all import AsyncSniffer  # type: ignore
        except ImportError as e:
            raise RuntimeError(
                "scapy is not installed. Install with `pip install scapy` "
                "to use live-capture mode, or run with --mode simulator."
            ) from e

        self._sniffer = AsyncSniffer(
            iface=self.iface,
            filter=self.bpf_filter,
            prn=self._on_packet,
            store=False,
        )
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass

    def pop_batch(self) -> List[Flow]:
        with self._lock:
            out = self._buffer
            self._buffer = []
        return out

    def _on_packet(self, pkt) -> None:  # pragma: no cover (needs root + traffic)
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore
        except Exception:
            return
        if IP not in pkt:
            return
        ip = pkt[IP]
        proto = "OTHER"
        sport = dport = 0
        if TCP in pkt:
            proto = "TCP"
            sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
        elif UDP in pkt:
            proto = "UDP"
            sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
        elif ICMP in pkt:
            proto = "ICMP"
        flow = Flow(
            ts=time.time(),
            src_ip=ip.src, dst_ip=ip.dst,
            src_port=sport, dst_port=dport,
            protocol=proto, length=int(len(pkt)),
        )
        with self._lock:
            self._buffer.append(flow)
