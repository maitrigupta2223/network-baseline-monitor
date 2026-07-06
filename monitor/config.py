"""Central configuration for the monitor.
 
All thresholds and tunables live here so a demo or evaluator can adjust
behavior without hunting through the codebase.
"""
import os
from dataclasses import dataclass, field
from typing import List


@dataclass
class Config:
    # ---- Capture / aggregation ----
    window_seconds: float = 1.0          # one feature window = 1 second
    history_windows: int = 180           # keep 3 minutes of history in memory
    warmup_windows: int = 30             # need this many windows before detection

    # ---- Statistical detector (z-score over baseline) ----
    z_threshold: float = 3.0             # |z| > this is anomalous
    z_metrics: List[str] = field(default_factory=lambda: [
        "packets", "bytes", "unique_src_ips", "unique_dst_ips",
        "unique_dst_ports", "tcp_packets", "udp_packets",
    ])

    # ---- Port-scan signature ----
    # Tuned for live home-network demos: nmap default scans 1000 ports, so
    # 15 within 10s is a safe lower bound that won't trigger on normal browsing.
    portscan_window_seconds: float = 10.0
    portscan_min_ports: int = 15
    portscan_min_dsts: int = 1

    # ---- DDoS signature ----
    # On a single home network you can't realistically generate 40 distinct
    # source IPs, so a single-source flood would be caught by the z-score
    # detector instead. Thresholds left high to avoid false positives.
    ddos_window_seconds: float = 5.0
    ddos_min_sources: int = 40
    ddos_min_pps: int = 80

    # ---- Data exfiltration signature ----
    # 2 MB outbound is enough to flag a deliberate large upload from a real
    # laptop without triggering on routine cloud sync.
    exfil_window_seconds: float = 10.0
    exfil_bytes_abs: int = 2 * 1024 * 1024
    exfil_bytes_ratio: float = 5.0           # OR > 5x baseline mean outbound

    # ---- Alerts ----
    alert_cooldown_seconds: float = 30.0     # dedupe identical alerts

    # ---- Internal CIDRs (used to classify in/out for exfil) ----
    internal_cidrs: List[str] = field(default_factory=lambda: [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    ])

    # ---- Storage ----
    sqlite_path: str = "data/monitor.db"

    # ---- Web ----
    host: str = "127.0.0.1"
    port: int = 5050

    def __post_init__(self) -> None:
        # Allow env-var overrides so Render (and other PaaS) can set
        # HOST / PORT without touching code. CLI args in main.py take
        # precedence because they're applied after construction.
        self.host = os.environ.get("HOST", self.host)
        self.port = int(os.environ.get("PORT", self.port))


CONFIG = Config()
