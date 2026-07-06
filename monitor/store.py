"""SQLite persistence for windows and alerts.

Kept intentionally tiny — students reviewing the project should be able to
read it end to end. Two tables: `windows` (one row per completed feature
window) and `alerts` (one row per de-duplicated detection).
"""
from __future__ import annotations
import json
import os
import sqlite3
import threading
from typing import List

from .alerts import Alert
from .features import Window


SCHEMA = """
CREATE TABLE IF NOT EXISTS windows (
    start_ts        REAL NOT NULL,
    end_ts          REAL NOT NULL,
    flows           INTEGER NOT NULL,
    packets         INTEGER NOT NULL,
    bytes           INTEGER NOT NULL,
    tcp_packets     INTEGER NOT NULL,
    udp_packets     INTEGER NOT NULL,
    icmp_packets    INTEGER NOT NULL,
    unique_src_ips  INTEGER NOT NULL,
    unique_dst_ips  INTEGER NOT NULL,
    unique_dst_ports INTEGER NOT NULL,
    PRIMARY KEY (start_ts)
);
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY,
    ts          REAL NOT NULL,
    type        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT NOT NULL,
    key         TEXT NOT NULL,
    evidence    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_windows_ts ON windows(end_ts);
"""


class Store:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.path = path
        self._lock = threading.Lock()
        # check_same_thread=False because the Flask request thread reads
        # while the engine thread writes.
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def persist_window(self, w: Window) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO windows VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    w.start_ts, w.end_ts, w.flows, w.packets, w.bytes,
                    w.tcp_packets, w.udp_packets, w.icmp_packets,
                    w.unique_src_ips, w.unique_dst_ips, w.unique_dst_ports,
                ),
            )
            self._conn.commit()

    def persist_alert(self, a: Alert) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO alerts VALUES (?,?,?,?,?,?,?,?)""",
                (
                    a.id, a.ts, a.type, a.severity, a.title, a.description,
                    a.key, json.dumps(a.evidence, default=str),
                ),
            )
            self._conn.commit()

    def recent_alerts(self, limit: int = 100) -> List[Alert]:
        with self._lock:
            cur = self._conn.execute(
                """SELECT id, ts, type, severity, title, description, key, evidence
                   FROM alerts ORDER BY id DESC LIMIT ?""",
                (limit,),
            )
            rows = cur.fetchall()
        out: List[Alert] = []
        for (aid, ts, typ, sev, title, desc, key, ev) in reversed(rows):
            try:
                evidence = json.loads(ev)
            except Exception:
                evidence = {}
            out.append(Alert(
                id=aid, ts=ts, type=typ, severity=sev,
                title=title, description=desc, key=key, evidence=evidence,
            ))
        return out

    def alert_count(self) -> int:
        with self._lock:
            cur = self._conn.execute("SELECT COUNT(*) FROM alerts")
            return int(cur.fetchone()[0])
