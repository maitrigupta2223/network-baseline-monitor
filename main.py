#!/usr/bin/env python3
"""Network Baseline Monitor — entry point.

Usage:
    python main.py                            # default: simulator mode
    python main.py --mode live --iface en0    # live capture (requires sudo)
    python main.py --port 5050
    python main.py --no-anomalies             # quiet baseline traffic only
"""
from __future__ import annotations
import argparse
import logging
import sys

from monitor.app import create_app
from monitor.config import CONFIG
from monitor.engine import Engine


def parse_args():
    p = argparse.ArgumentParser(description="Network Baseline Monitor")
    p.add_argument("--mode", choices=["simulator", "live"], default="simulator",
                   help="data source: synthetic simulator or live packet capture")
    p.add_argument("--iface", default=None,
                   help="network interface for live mode (e.g. en0, eth0)")
    p.add_argument("--bpf", default="ip",
                   help="BPF filter for live mode (default: 'ip')")
    p.add_argument("--seed", type=int, default=None,
                   help="simulator RNG seed (omit for time-based randomness)")
    p.add_argument("--no-anomalies", action="store_true",
                   help="simulator: emit only baseline traffic, no attacks")
    p.add_argument("--host", default=CONFIG.host)
    p.add_argument("--port", type=int, default=CONFIG.port)
    p.add_argument("--db", default=CONFIG.sqlite_path,
                   help="SQLite path for persistence")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    CONFIG.host, CONFIG.port = args.host, args.port
    CONFIG.sqlite_path = args.db

    if args.mode == "simulator":
        from monitor.simulator import Simulator
        source = Simulator(seed=args.seed,
                           inject_anomalies=not args.no_anomalies)
        print(f"[boot] source = simulator (anomalies={'on' if not args.no_anomalies else 'off'})")
    else:
        try:
            from monitor.capture import LiveCapture
        except Exception as e:
            print(f"[boot] live capture unavailable: {e}")
            return 2
        source = LiveCapture(iface=args.iface, bpf_filter=args.bpf)
        print(f"[boot] source = live (iface={args.iface or 'default'}, bpf='{args.bpf}')")
        print("[boot] live mode requires elevated privileges (sudo) on most systems.")

    engine = Engine(source=source, cfg=CONFIG)
    engine.start()
    print(f"[boot] engine started; warmup = {CONFIG.warmup_windows} windows "
          f"({CONFIG.window_seconds:.1f}s each)")

    app = create_app(engine, CONFIG)
    print(f"[boot] dashboard:  http://{CONFIG.host}:{CONFIG.port}/")
    print()
    print("[boot] alerts will print here as they fire, in this format:")
    print("[boot]   [HH:MM:SS] [ALERT/SEVERITY] [type] description")
    print("[boot] press Ctrl+C to stop.")
    print("-" * 72)

    # Silence Flask's per-request log lines (one per second from /api/state
    # polling) so the alert output stays readable.
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    try:
        app.run(host=CONFIG.host, port=CONFIG.port, debug=False, threaded=True,
                use_reloader=False)
    finally:
        engine.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
