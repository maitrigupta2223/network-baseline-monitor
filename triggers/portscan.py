"""Trigger a port scan against a target you own.

Usage:
    python triggers/portscan.py 192.168.1.1
    python triggers/portscan.py            # auto-detects the default gateway

Prefers `nmap` (fast, well-known) and falls back to a pure-Python TCP
connect scan if nmap isn't installed. Either approach generates real
packets that the live monitor will see.

⚠️ Only scan devices you own (your laptop, your home router).
"""
from __future__ import annotations
import shutil
import socket
import subprocess
import sys
import threading
import time


def detect_default_gateway() -> str | None:
    """Best-effort default-gateway lookup across Windows / macOS / Linux."""
    try:
        if sys.platform.startswith("win"):
            out = subprocess.check_output(["ipconfig"], text=True, timeout=5)
            for line in out.splitlines():
                if "Default Gateway" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        ip = parts[-1].strip()
                        if ip and ip[0].isdigit():
                            return ip
        else:
            # macOS: `netstat -nr`; Linux: `ip route` — try both.
            try:
                out = subprocess.check_output(["netstat", "-nr"], text=True, timeout=5)
                for line in out.splitlines():
                    if line.startswith(("default", "0.0.0.0")):
                        parts = line.split()
                        if len(parts) >= 2 and parts[1][0].isdigit():
                            return parts[1]
            except Exception:
                pass
            try:
                out = subprocess.check_output(["ip", "route"], text=True, timeout=5)
                for line in out.splitlines():
                    if line.startswith("default"):
                        parts = line.split()
                        if "via" in parts:
                            return parts[parts.index("via") + 1]
            except Exception:
                pass
    except Exception:
        pass
    return None


def run_nmap(target: str, ports: str = "1-200") -> int:
    print(f"[*] nmap -p {ports} {target}")
    return subprocess.call(["nmap", "-p", ports, target])


def run_python_scan(target: str, lo: int = 1, hi: int = 200,
                    parallel: int = 50) -> int:
    """Pure-Python TCP connect scan — slower than nmap but no install needed."""
    print(f"[*] connecting to {target}:{lo}-{hi} ({hi - lo + 1} ports)...")
    open_ports: list[int] = []
    sem = threading.Semaphore(parallel)

    def probe(port: int) -> None:
        with sem:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4)
            try:
                if s.connect_ex((target, port)) == 0:
                    open_ports.append(port)
            finally:
                s.close()

    threads = [threading.Thread(target=probe, args=(p,)) for p in range(lo, hi + 1)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print(f"[*] open ports: {sorted(open_ports) or '(none)'}")
    return 0


def main(argv: list[str]) -> int:
    target = argv[1] if len(argv) > 1 else (detect_default_gateway() or "127.0.0.1")
    print("=" * 60)
    print(" PORT-SCAN TRIGGER")
    print("=" * 60)
    print(f" target: {target}")
    print(" only scan devices you own (router, laptop, home server).")
    print(" expected dashboard alert: port-scan signature within ~10s")
    print("=" * 60)
    time.sleep(0.5)

    if shutil.which("nmap"):
        return run_nmap(target)
    print("[*] nmap not found; falling back to pure-Python TCP scan.")
    print("[*] tip: install nmap from https://nmap.org for faster scans.")
    return run_python_scan(target)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
