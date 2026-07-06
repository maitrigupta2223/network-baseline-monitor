"""Synthetic traffic generator.

Produces a realistic stream of Flow records — a slowly-varying baseline plus
periodic anomalies (port-scan, DDoS, data exfiltration) — so the system can
be demonstrated end-to-end without packet-capture privileges.

The generator is deterministic-ish (seedable) but uses time-based jitter so
charts look organic during a live demo.
"""
from __future__ import annotations
import math
import random
import threading
import time
from typing import Callable, List, Optional

from .flow import Flow


# A small pool of "internal" hosts and "external" peers — chosen so the
# dashboard's top-talkers list is readable rather than visually noisy.
INTERNAL_HOSTS = [f"192.168.1.{i}" for i in range(10, 30)]
EXTERNAL_HOSTS = [
    "8.8.8.8", "1.1.1.1", "13.107.42.14", "142.250.190.46",
    "151.101.1.69", "104.16.132.229", "20.190.190.1", "172.217.5.110",
    "23.45.123.10", "52.96.165.34", "162.159.135.234",
]
COMMON_DST_PORTS = [80, 443, 53, 22, 25, 110, 143, 3306, 6379, 8080, 8443]


class Simulator:
    """Threaded flow generator. Call .start(), consume via .pop_batch()."""

    def __init__(self, seed: Optional[int] = None,
                 base_pps: float = 60.0,
                 inject_anomalies: bool = True):
        self._rng = random.Random(seed)
        self._base_pps = base_pps
        self._inject = inject_anomalies
        self._lock = threading.Lock()
        self._buffer: List[Flow] = []
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._t0 = time.time()

        # When the next anomaly of each kind fires (epoch seconds).
        # Spaced out so the dashboard tells a clear story during a demo:
        #   ~40s in: first port scan
        #   ~80s in: DDoS
        #   ~125s in: data exfiltration burst
        # After that they recur on long jittered cooldowns so the alerts
        # feed stays readable instead of flooding.
        now = self._t0
        self._next_portscan = now + 40
        self._next_ddos = now + 80
        self._next_exfil = now + 125

    # ---- lifecycle ----
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="simulator")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    # ---- consumer API ----
    def pop_batch(self) -> List[Flow]:
        with self._lock:
            out = self._buffer
            self._buffer = []
        return out

    # ---- internals ----
    def _emit(self, flow: Flow) -> None:
        with self._lock:
            self._buffer.append(flow)

    def _run(self) -> None:
        # We tick at ~20 Hz; each tick emits a Poisson-ish number of flows
        # so per-second counts have natural variance.
        tick_hz = 20.0
        dt = 1.0 / tick_hz
        while not self._stop.is_set():
            now = time.time()
            self._tick_baseline(now, dt)
            if self._inject:
                self._maybe_inject(now)
            time.sleep(dt)

    def _tick_baseline(self, now: float, dt: float) -> None:
        # Diurnal-ish modulation gives the baseline a gentle wave so the
        # rolling mean isn't perfectly flat — looks realistic on charts.
        elapsed = now - self._t0
        modulation = 1.0 + 0.20 * math.sin(elapsed / 30.0)
        rate = self._base_pps * modulation
        # number of flows in this tick: Poisson with mean (rate * dt)
        n = self._poisson(rate * dt)
        for _ in range(n):
            self._emit(self._random_baseline_flow(now))

    def _random_baseline_flow(self, now: float) -> Flow:
        rng = self._rng
        # 80% outbound (internal -> external), 20% inbound replies
        if rng.random() < 0.8:
            src = rng.choice(INTERNAL_HOSTS)
            dst = rng.choice(EXTERNAL_HOSTS)
        else:
            src = rng.choice(EXTERNAL_HOSTS)
            dst = rng.choice(INTERNAL_HOSTS)
        proto = rng.choices(["TCP", "UDP", "ICMP"], weights=[80, 18, 2], k=1)[0]
        if proto == "ICMP":
            return Flow(now, src, dst, 0, 0, proto, rng.randint(64, 128))
        dst_port = rng.choices(
            COMMON_DST_PORTS + [rng.randint(1024, 65535)],
            weights=[40, 40, 20, 5, 3, 3, 3, 2, 2, 5, 3, 14],
            k=1,
        )[0]
        src_port = rng.randint(1024, 65535)
        # heavy-tailed length: most are small, occasional large
        if rng.random() < 0.85:
            length = rng.randint(60, 800)
        else:
            length = rng.randint(800, 12000)
        return Flow(now, src, dst, src_port, dst_port, proto, length)

    # ---- anomaly injectors ----
    def _maybe_inject(self, now: float) -> None:
        # Long recurrence so a 5-minute demo shows each attack once, not
        # a wall of repeats. The alert manager's cooldown also dedupes
        # but spacing is friendlier to a viewer reading the feed.
        if now >= self._next_portscan:
            self._inject_port_scan(now)
            self._next_portscan = now + self._rng.uniform(180, 300)
        if now >= self._next_ddos:
            self._inject_ddos(now)
            self._next_ddos = now + self._rng.uniform(180, 300)
        if now >= self._next_exfil:
            self._inject_exfiltration(now)
            self._next_exfil = now + self._rng.uniform(200, 320)

    def _inject_port_scan(self, now: float) -> None:
        # one attacker IP probes ~80 distinct ports against one target,
        # spread over ~3 seconds.
        attacker = f"203.0.113.{self._rng.randint(2, 250)}"
        target = self._rng.choice(INTERNAL_HOSTS)
        ports = self._rng.sample(range(20, 1024), 80)
        spread = 3.0
        for i, p in enumerate(ports):
            t = now + (i / len(ports)) * spread
            self._emit(Flow(
                ts=t, src_ip=attacker, dst_ip=target,
                src_port=self._rng.randint(40000, 65000),
                dst_port=p, protocol="TCP", length=60,
            ))

    def _inject_ddos(self, now: float) -> None:
        # ~400 packets from many distinct source IPs slamming one internal
        # target with SYNs over ~1.5 seconds. Aggressive on purpose so the
        # signature detector fires alongside the statistical one.
        target = self._rng.choice(INTERNAL_HOSTS)
        spread = 1.5
        n = 400
        for i in range(n):
            # vary second octet for plenty of distinct sources
            src = f"198.51.{self._rng.randint(0, 50)}.{self._rng.randint(1, 254)}"
            t = now + (i / n) * spread
            self._emit(Flow(
                ts=t, src_ip=src, dst_ip=target,
                src_port=self._rng.randint(1024, 65000),
                dst_port=self._rng.choice([80, 443]),
                protocol="TCP", length=64,
            ))

    def _inject_exfiltration(self, now: float) -> None:
        # one internal host pushes ~12 MB to one external IP over ~4 seconds
        src = self._rng.choice(INTERNAL_HOSTS)
        dst = f"185.199.{self._rng.randint(0, 250)}.{self._rng.randint(1, 254)}"
        total_bytes = 12 * 1024 * 1024
        chunks = 800
        chunk = total_bytes // chunks
        spread = 4.0
        for i in range(chunks):
            t = now + (i / chunks) * spread
            self._emit(Flow(
                ts=t, src_ip=src, dst_ip=dst,
                src_port=self._rng.randint(40000, 65000),
                dst_port=443, protocol="TCP", length=chunk,
            ))

    # ---- math ----
    def _poisson(self, lam: float) -> int:
        # Knuth's algorithm — fine for the small means we use here.
        if lam <= 0:
            return 0
        L = math.exp(-lam)
        k = 0
        p = 1.0
        while True:
            k += 1
            p *= self._rng.random()
            if p <= L:
                return k - 1


def make_simulator(**kwargs) -> Simulator:
    return Simulator(**kwargs)
