"""Flow record — one observed packet/connection summary."""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class Flow:
    ts: float          # epoch seconds
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str      # "TCP" | "UDP" | "ICMP" | "OTHER"
    length: int        # bytes
