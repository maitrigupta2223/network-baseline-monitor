"""Alert manager: dedupe, persist, and expose recent alerts."""
from __future__ import annotations
import sys
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any, Deque, Dict, List, Optional

from .detector import Detection


def _print_alert_line(a: "Alert") -> None:
    """Print each new alert to stdout so it's visible in the CMD window
    in real time. Format is plain ASCII so it renders correctly on
    Windows CMD, PowerShell, macOS Terminal, and Linux."""
    ts = time.strftime("%H:%M:%S", time.localtime(a.ts))
    sev = a.severity.upper()
    line = f"[{ts}] [ALERT/{sev}] [{a.type}] {a.description}"
    print(line, flush=True, file=sys.stdout)


@dataclass
class Alert:
    id: int
    ts: float
    type: str
    severity: str
    title: str
    description: str
    key: str
    evidence: Dict[str, Any] = field(default_factory=dict)


class AlertManager:
    def __init__(self, cooldown_seconds: float, store=None,
                 max_in_memory: int = 500):
        self.cooldown = cooldown_seconds
        self.store = store
        self._last_seen: Dict[str, float] = {}
        self._alerts: Deque[Alert] = deque(maxlen=max_in_memory)
        self._lock = threading.Lock()
        self._next_id = 1
        # warm the in-memory feed from persisted alerts so the dashboard isn't
        # empty after a restart.
        if store is not None:
            try:
                for a in store.recent_alerts(limit=100):
                    self._alerts.append(a)
                    self._next_id = max(self._next_id, a.id + 1)
            except Exception:
                pass

    def submit(self, detections: List[Detection]) -> List[Alert]:
        new: List[Alert] = []
        now = time.time()
        with self._lock:
            for d in detections:
                last = self._last_seen.get(d.key, 0.0)
                if now - last < self.cooldown:
                    continue
                self._last_seen[d.key] = now
                a = Alert(
                    id=self._next_id, ts=d.ts or now,
                    type=d.type, severity=d.severity,
                    title=d.title, description=d.description,
                    key=d.key, evidence=d.evidence,
                )
                self._next_id += 1
                self._alerts.append(a)
                new.append(a)
                if self.store is not None:
                    try:
                        self.store.persist_alert(a)
                    except Exception:
                        pass
                _print_alert_line(a)
        return new

    def recent(self, limit: int = 100) -> List[Dict]:
        with self._lock:
            xs = list(self._alerts)[-limit:]
        xs.reverse()
        return [asdict(a) for a in xs]

    def count_by_severity(self) -> Dict[str, int]:
        out = {"info": 0, "warning": 0, "critical": 0}
        with self._lock:
            for a in self._alerts:
                out[a.severity] = out.get(a.severity, 0) + 1
        return out
