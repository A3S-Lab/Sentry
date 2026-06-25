"""Read sentry's Prometheus ``/metrics`` and ``/healthz`` (served when A3S_SENTRY_METRICS_ADDR is set)."""

from __future__ import annotations

import urllib.request
from dataclasses import dataclass


@dataclass
class MetricsSnapshot:
    events: int = 0
    blocked: int = 0
    overload_degraded: int = 0  # escalations that fell through to the fail mode — alarm on a rising rate
    enforce_failed: int = 0  # a block whose deny-write errored — alarm on a rising rate


_NAMES = {
    "sentry_events_total": "events",
    "sentry_blocked_total": "blocked",
    "sentry_overload_degraded_total": "overload_degraded",
    "sentry_enforce_failed_total": "enforce_failed",
}


def parse_metrics(text: str) -> MetricsSnapshot:
    snap = MetricsSnapshot()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] in _NAMES:
            try:
                setattr(snap, _NAMES[parts[0]], int(float(parts[1])))
            except ValueError:
                pass
    return snap


class MetricsClient:
    """Reads sentry's metrics endpoint. ``addr`` is ``"host:port"`` or a full ``http://...`` URL."""

    def __init__(self, addr: str) -> None:
        self.base = addr.rstrip("/") if addr.startswith("http") else f"http://{addr}"

    def health(self, timeout: float = 2.0) -> bool:
        try:
            with urllib.request.urlopen(self.base + "/healthz", timeout=timeout) as r:
                return r.status == 200
        except Exception:
            return False

    def metrics(self, timeout: float = 2.0) -> MetricsSnapshot:
        with urllib.request.urlopen(self.base + "/metrics", timeout=timeout) as r:
            return parse_metrics(r.read().decode())
