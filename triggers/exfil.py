"""Trigger a data-exfiltration alert by uploading random data to a public
file-sharing service.

Usage:
    python triggers/exfil.py             # 5 MB upload (default)
    python triggers/exfil.py 10          # 10 MB upload

This sends real bytes across your network, so the monitor (in live mode)
will count them as outbound traffic from your internal IP to an external
IP — which is exactly the data-exfiltration signature.
"""
from __future__ import annotations
import os
import sys
import time
import urllib.request


UPLOAD_URL = "https://transfer.sh/test-{ts}.bin"


def upload(size_mb: int) -> int:
    size = size_mb * 1024 * 1024
    print(f"[*] generating {size_mb} MB of random data in memory...")
    data = os.urandom(size)
    url = UPLOAD_URL.format(ts=int(time.time()))
    print(f"[*] PUT {url}")
    req = urllib.request.Request(url, data=data, method="PUT",
                                 headers={"Content-Type": "application/octet-stream"})
    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            body = r.read().decode("utf-8", "replace").strip()
            elapsed = time.time() - started
            mbps = (size / 1024 / 1024) / max(elapsed, 0.01)
            print(f"[*] uploaded {size_mb} MB in {elapsed:.1f}s ({mbps:.2f} MB/s)")
            print(f"[*] response: {body[:200]}")
        return 0
    except Exception as e:
        print(f"[!] upload failed: {e}")
        print("[!] transfer.sh may be temporarily down — retrying with a")
        print("    different free service (0x0.st)...")
        try:
            import urllib.parse
            boundary = "----nbm-trigger-boundary"
            body_parts = [
                f"--{boundary}\r\n".encode(),
                b'Content-Disposition: form-data; name="file"; filename="x.bin"\r\n',
                b"Content-Type: application/octet-stream\r\n\r\n",
                data,
                f"\r\n--{boundary}--\r\n".encode(),
            ]
            payload = b"".join(body_parts)
            req2 = urllib.request.Request(
                "https://0x0.st",
                data=payload,
                method="POST",
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}",
                         "User-Agent": "nbm-trigger/1.0"},
            )
            with urllib.request.urlopen(req2, timeout=60) as r:
                print(f"[*] uploaded via 0x0.st: {r.read().decode().strip()}")
            return 0
        except Exception as e2:
            print(f"[!] fallback also failed: {e2}")
            return 1


def main(argv: list[str]) -> int:
    size_mb = int(argv[1]) if len(argv) > 1 else 5
    print("=" * 60)
    print(" DATA-EXFILTRATION TRIGGER")
    print("=" * 60)
    print(f" volume: {size_mb} MB outbound to a public file-sharing service")
    print(" expected dashboard alert: exfil signature within ~10s")
    print("=" * 60)
    time.sleep(0.5)
    return upload(size_mb)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
