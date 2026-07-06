"""Statistical baseline of normal traffic.

We keep a rolling history of per-window metric values and, for each metric,
expose the running mean and standard deviation. Detection layers consume
these to compute z-scores.

Design notes:
- Plain stdlib (no numpy) to keep deployment simple.
- Anomalous windows are *not* fed back into the baseline — otherwise a long
  attack would drag the baseline up and mask itself ("self-poisoning").
- We require a minimum number of clean samples (warmup) before any z-score
  is reported as meaningful.
"""
from __future__ import annotations
import statistics
from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional


@dataclass
class BaselineStat:
    metric: str
    mean: float
    stdev: float
    n: int


class Baseline:
    def __init__(self, history_size: int, warmup: int, metrics: List[str]):
        self.history_size = history_size
        self.warmup = warmup
        self.metrics = metrics
        # one deque of recent CLEAN samples per metric
        self._hist: Dict[str, Deque[float]] = {
            m: deque(maxlen=history_size) for m in metrics
        }

    @property
    def is_warm(self) -> bool:
        return all(len(self._hist[m]) >= self.warmup for m in self.metrics)

    def update(self, metric_values: Dict[str, float]) -> None:
        """Record a clean (non-anomalous) window's metrics."""
        for m, v in metric_values.items():
            if m in self._hist:
                self._hist[m].append(float(v))

    def stat(self, metric: str) -> Optional[BaselineStat]:
        d = self._hist.get(metric)
        if d is None or len(d) < 2:
            return None
        mean = statistics.fmean(d)
        # population stdev — we treat the deque as the full known history
        stdev = statistics.pstdev(d) if len(d) >= 2 else 0.0
        return BaselineStat(metric=metric, mean=mean, stdev=stdev, n=len(d))

    def zscore(self, metric: str, value: float) -> Optional[float]:
        s = self.stat(metric)
        if s is None or s.stdev == 0:
            # No variance yet — undefined z-score. Treat as 0 to avoid
            # spurious alerts during a quiet network.
            return 0.0 if s is not None else None
        return (value - s.mean) / s.stdev

    def snapshot(self) -> Dict[str, Dict[str, float]]:
        out: Dict[str, Dict[str, float]] = {}
        for m in self.metrics:
            s = self.stat(m)
            if s is None:
                out[m] = {"mean": 0.0, "stdev": 0.0, "n": 0}
            else:
                out[m] = {"mean": s.mean, "stdev": s.stdev, "n": s.n}
        return out
