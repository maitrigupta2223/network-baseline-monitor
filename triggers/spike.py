"""Trigger a statistical (z-score) anomaly by firing many parallel HTTPS
requests in a short burst.

Usage:
    python triggers/spike.py                   # 50 parallel requests (default)
    python triggers/spike.py 100               # 100 parallel requests
    python triggers/spike.py 50 https://www.python.org/   # custom URL

This is what the "unknown attack" demo scenario looks like to the
detector — the system has never seen this specific pattern, but it
recognises that traffic is many standard deviations above the learned
baseline and fires the z-score detector.
"""
from __future__ import annotations
import concurrent.futures as cf
import sys
import time
import urllib.request


DEFAULT_URL = "https://www.wikipedia.org/"


def hit(url: str, idx: int) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=8) as r:
            r.read(1024)
        return idx, "ok"
    except Exception as e:
        return idx, f"err: {e.__class__.__name__}"


def main(argv: list[str]) -> int:
    n = int(argv[1]) if len(argv) > 1 else 50
    url = argv[2] if len(argv) > 2 else DEFAULT_URL
    print("=" * 60)
    print(" STATISTICAL ANOMALY (TRAFFIC SPIKE) TRIGGER")
    print("=" * 60)
    print(f" requests: {n} parallel GETs to {url}")
    print(" expected dashboard alert: z-score anomaly within ~5s")
    print("=" * 60)
    time.sleep(0.5)

    started = time.time()
    with cf.ThreadPoolExecutor(max_workers=n) as ex:
        futures = [ex.submit(hit, url, i) for i in range(n)]
        ok = err = 0
        for f in cf.as_completed(futures):
            _, status = f.result()
            if status == "ok":
                ok += 1
            else:
                err += 1
    elapsed = time.time() - started
    print(f"[*] done in {elapsed:.1f}s — {ok} ok, {err} errors")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
