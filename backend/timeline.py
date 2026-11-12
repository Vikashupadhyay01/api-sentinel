"""
backend/timeline.py – Rolling time-series aggregation for API-Sentinel.

Maintains 15-minute history in 10-second buckets for:
  - Request volume
  - Security alerts raised
  - Blocked requests (enforcement actions)

Provides data for the dashboard's live activity chart and PDF reports.
"""
from __future__ import annotations

import bisect
import datetime
import time
from dataclasses import dataclass, field
from typing import Any, Sequence


def _parse_ts_to_epoch(ts: str | float | int | None) -> float:
    """Safely convert ISO timestamp string or epoch number to epoch float."""
    if ts is None:
        return time.time()
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, str):
        # Handle ISO-8601 strings like "2026-11-09T14:05:00.123456Z" or "+00:00"
        s = ts.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.datetime.fromisoformat(s)
            return dt.timestamp()
        except Exception:
            try:
                return float(ts)
            except Exception:
                return time.time()
    return time.time()


@dataclass
class TimePoint:
    epoch: float
    kind: str  # "request", "alert", "blocked"


class TimelineTracker:
    """Tracks event timestamps in a ring / sorted buffer to compute 10-second buckets."""

    def __init__(self, window_seconds: int = 900, bucket_size: int = 10) -> None:
        self.window_seconds = window_seconds  # Default 15 minutes
        self.bucket_size = bucket_size        # Default 10 seconds
        self._request_epochs: list[float] = []
        self._alert_epochs: list[float] = []
        self._blocked_epochs: list[float] = []
        self._latest_epoch: float = 0.0

    def record_request(self, ts: str | float | None = None) -> None:
        ep = _parse_ts_to_epoch(ts)
        self._request_epochs.append(ep)
        if ep > self._latest_epoch:
            self._latest_epoch = ep

    def record_alert(self, ts: str | float | None = None) -> None:
        ep = _parse_ts_to_epoch(ts)
        self._alert_epochs.append(ep)
        if ep > self._latest_epoch:
            self._latest_epoch = ep

    def record_blocked(self, ts: str | float | None = None) -> None:
        ep = _parse_ts_to_epoch(ts)
        self._blocked_epochs.append(ep)
        if ep > self._latest_epoch:
            self._latest_epoch = ep

    def clear(self) -> None:
        """Reset all tracked timestamps."""
        self._request_epochs.clear()
        self._alert_epochs.clear()
        self._blocked_epochs.clear()
        self._latest_epoch = 0.0

    def get_buckets(self, end_epoch: float | None = None) -> list[dict[str, Any]]:
        """Return a list of bucket dicts for the last window_seconds.

        Each bucket contains:
          - start_epoch: float
          - label: "HH:MM:SS"
          - requests: int
          - alerts: int
          - blocked: int
        """
        now = time.time()
        # Anchor window at max(now, latest_epoch seen) so historical replay or slight clock skew works
        anchor = end_epoch if end_epoch is not None else max(now, self._latest_epoch)
        if anchor <= 0:
            anchor = now

        # Align anchor to the nearest bucket_size boundary
        anchor_aligned = (int(anchor) // self.bucket_size) * self.bucket_size + self.bucket_size
        num_buckets = self.window_seconds // self.bucket_size
        start_aligned = anchor_aligned - (num_buckets * self.bucket_size)

        # Pre-sort lists if needed (usually append is monotonic)
        req_epochs = sorted(self._request_epochs)
        alt_epochs = sorted(self._alert_epochs)
        blk_epochs = sorted(self._blocked_epochs)

        buckets: list[dict[str, Any]] = []

        for i in range(num_buckets):
            b_start = start_aligned + (i * self.bucket_size)
            b_end = b_start + self.bucket_size

            # Count items in [b_start, b_end) using binary search for speed
            r_count = bisect.bisect_left(req_epochs, b_end) - bisect.bisect_left(req_epochs, b_start)
            a_count = bisect.bisect_left(alt_epochs, b_end) - bisect.bisect_left(alt_epochs, b_start)
            b_count = bisect.bisect_left(blk_epochs, b_end) - bisect.bisect_left(blk_epochs, b_start)

            # Local time string for display
            dt = datetime.datetime.fromtimestamp(b_start)
            label = dt.strftime("%H:%M:%S")

            buckets.append({
                "start_epoch": b_start,
                "label": label,
                "requests": r_count,
                "alerts": a_count,
                "blocked": b_count,
            })

        return buckets

