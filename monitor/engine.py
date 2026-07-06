"""Orchestrates the pipeline: source -> features -> baseline -> detector -> alerts.

A single background thread drains the configured source (simulator or live
capture) at ~10 Hz, hands flows to the WindowAggregator, and on each
completed window updates the baseline (if clean), runs detection, and
submits any detections to the AlertManager.

The engine keeps a small in-memory ring of recent window summaries so the
dashboard can render time-series charts without re-reading SQLite.
"""
from __future__ import annotations
import threading
import time
from collections import deque
from dataclasses import asdict
from typing import Any, Deque, Dict, List, Optional

from .alerts import Alert, AlertManager
from .baseline import Baseline
from .config import CONFIG, Config
from .detector import CompositeDetector, Detection
from .features import Window, WindowAggregator
from .flow import Flow
from .store import Store


class Engine:
    def __init__(self,
                 source,                 # has .start/.stop/.pop_batch
                 cfg: Optional[Config] = None,
                 store: Optional[Store] = None):
        self.cfg = cfg or CONFIG
        self.source = source
        self.store = store or Store(self.cfg.sqlite_path)
        self.baseline = Baseline(
            history_size=self.cfg.history_windows,
            warmup=self.cfg.warmup_windows,
            metrics=self.cfg.z_metrics,
        )
        self.detector = CompositeDetector(self.cfg, self.baseline)
        self.alerts = AlertManager(
            cooldown_seconds=self.cfg.alert_cooldown_seconds,
            store=self.store,
        )
        self.aggregator = WindowAggregator(self.cfg.window_seconds)

        # Recent window summaries for charts (most recent last).
        self._recent: Deque[Dict[str, Any]] = deque(maxlen=self.cfg.history_windows)
        self._latest_window: Optional[Window] = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._started_at: Optional[float] = None
        # totals for KPI tiles
        self._total_flows = 0
        self._total_bytes = 0

    # ---- lifecycle ----
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self.source.start()
        self._started_at = time.time()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="engine")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self.source.stop()
        except Exception:
            pass
        if self._thread:
            self._thread.join(timeout=2)

    # ---- core loop ----
    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                batch = self.source.pop_batch()
                if batch:
                    with self._lock:
                        self._total_flows += len(batch)
                        self._total_bytes += sum(f.length for f in batch)
                    self.aggregator.ingest(batch)
                completed = self.aggregator.drain_completed(time.time())
                for w in completed:
                    self._on_window(w)
            except Exception as e:
                # never let the engine crash silently — surface as a synthetic alert
                print(f"[engine] error: {e}")
            time.sleep(0.1)

    def _on_window(self, w: Window) -> None:
        # detect first; if window has no detections we treat it as 'clean'
        # and feed it to the baseline.
        detections = self.detector.detect(w)
        is_clean = len(detections) == 0
        if is_clean:
            self.baseline.update(w.metrics())

        new_alerts = self.alerts.submit(detections)

        # build a compact summary for the dashboard
        summary = self._summarize(w, detections, new_alerts)
        with self._lock:
            self._recent.append(summary)
            self._latest_window = w

        # persist the window so the SQLite file is useful for later analysis
        try:
            self.store.persist_window(w)
        except Exception:
            pass

    def _summarize(self, w: Window,
                   detections: List[Detection],
                   alerts: List[Alert]) -> Dict[str, Any]:
        return {
            "start_ts": w.start_ts,
            "end_ts": w.end_ts,
            "packets": w.packets,
            "bytes": w.bytes,
            "tcp_packets": w.tcp_packets,
            "udp_packets": w.udp_packets,
            "icmp_packets": w.icmp_packets,
            "unique_src_ips": w.unique_src_ips,
            "unique_dst_ips": w.unique_dst_ips,
            "unique_dst_ports": w.unique_dst_ports,
            "anomalous": len(detections) > 0,
            "new_alert_ids": [a.id for a in alerts],
        }

    # ---- read API for the web layer ----
    def state(self, history_n: int = 120) -> Dict[str, Any]:
        with self._lock:
            recent = list(self._recent)[-history_n:]
            latest = self._latest_window
            total_flows = self._total_flows
            total_bytes = self._total_bytes
            started_at = self._started_at

        baseline_snap = self.baseline.snapshot()

        if latest is None:
            top_talkers, top_ports, proto = [], [], {}
        else:
            top_talkers = latest.top_talkers(10)
            top_ports = latest.top_dst_ports(10)
            proto = latest.proto_breakdown()

        # current pps/bps come from the most recent completed window
        current_pps = recent[-1]["packets"] if recent else 0
        current_bps = recent[-1]["bytes"] if recent else 0

        # prepare baseline overlay for the packets chart
        bstat_pkts = baseline_snap.get("packets", {"mean": 0, "stdev": 0})
        bstat_bytes = baseline_snap.get("bytes", {"mean": 0, "stdev": 0})

        return {
            "status": "monitoring" if self.baseline.is_warm else "training",
            "started_at": started_at,
            "uptime_seconds": (time.time() - started_at) if started_at else 0,
            "total_flows": total_flows,
            "total_bytes": total_bytes,
            "current_pps": current_pps,
            "current_bps": current_bps,
            "warmup_progress": min(1.0, len(recent) / max(1, self.cfg.warmup_windows)),
            "baseline": baseline_snap,
            "baseline_overlay": {
                "packets": bstat_pkts,
                "bytes": bstat_bytes,
            },
            "recent_windows": recent,
            "top_talkers": top_talkers,
            "top_dst_ports": top_ports,
            "protocol_breakdown": proto,
            "alert_summary": self.alerts.count_by_severity(),
            "config": {
                "window_seconds": self.cfg.window_seconds,
                "z_threshold": self.cfg.z_threshold,
                "warmup_windows": self.cfg.warmup_windows,
                "portscan_min_ports": self.cfg.portscan_min_ports,
                "ddos_min_sources": self.cfg.ddos_min_sources,
                "exfil_bytes_abs": self.cfg.exfil_bytes_abs,
            },
        }

    def recent_alerts(self, limit: int = 100):
        return self.alerts.recent(limit=limit)
