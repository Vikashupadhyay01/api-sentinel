"""
backend/ratelimit.py – Sliding-window rate limiter and bot-detection heuristics.

OWASP mapping
-------------
  - Excessive requests per user/IP  → API4 (Unrestricted Resource Consumption)
  - Rapid sequential ID enumeration → API6 (Unrestricted Access to Sensitive
                                             Business Flows / Enumeration)

Algorithm
---------
Rate limiting
  For each (user OR ip, endpoint_pattern) pair we maintain a deque of
  hit timestamps.  On every new hit we:
    1. Evict timestamps older than the window.
    2. Append the new timestamp.
    3. If len(deque) > limit → emit a RATE_LIMIT Alert.

Bot / enumeration detection
  Tracks sequences of *numeric* path IDs accessed by the same user within a
  short burst window.  If a user accesses ≥ ENUM_THRESHOLD distinct integer IDs
  on the same endpoint pattern within ENUM_WINDOW_S seconds, we classify it as
  sequential enumeration and emit an ENUM Alert.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Iterable, Optional

from backend.bola import Alert, _make_alert
from backend.discovery import normalize_path
from backend.parser import Record


# ---------------------------------------------------------------------------
# Configuration defaults (all tuneable at construction time)
# ---------------------------------------------------------------------------

DEFAULT_RATE_LIMIT: int = 30          # max requests per window per key
DEFAULT_WINDOW_S: float = 60.0        # sliding window length in seconds
DEFAULT_ENUM_THRESHOLD: int = 10      # distinct IDs in burst = enumeration
DEFAULT_ENUM_WINDOW_S: float = 10.0   # burst window for enumeration


# ---------------------------------------------------------------------------
# Rate-limit detector
# ---------------------------------------------------------------------------

@dataclass
class _Window:
    """A deque of hit timestamps (float epoch seconds) for one key."""
    hits: Deque[float] = field(default_factory=deque)


class RateLimitDetector:
    """Sliding-window rate limiter with enumeration-burst detection.

    Parameters
    ----------
    rate_limit:
        Maximum allowed requests per *window_s* seconds for a single key.
    window_s:
        Length of the sliding window in seconds.
    enum_threshold:
        Number of *distinct* numeric IDs on the same endpoint pattern within
        *enum_window_s* seconds that triggers an enumeration alert.
    enum_window_s:
        Burst window for enumeration detection (seconds).
    """

    def __init__(
        self,
        rate_limit: int = DEFAULT_RATE_LIMIT,
        window_s: float = DEFAULT_WINDOW_S,
        enum_threshold: int = DEFAULT_ENUM_THRESHOLD,
        enum_window_s: float = DEFAULT_ENUM_WINDOW_S,
    ) -> None:
        self.rate_limit = rate_limit
        self.window_s = window_s
        self.enum_threshold = enum_threshold
        self.enum_window_s = enum_window_s

        # Sliding-window state: key → _Window
        # Key = (identity, norm_path)  where identity = user or "ip:<addr>"
        self._windows: dict[tuple[str, str], _Window] = {}

        # Enumeration state: (identity, norm_path) → list of (ts, obj_id) tuples
        self._enum_hits: dict[tuple[str, str], list[tuple[float, str]]] = {}

        # Already-alerted rate-limit keys (reset per 2× window to re-alert)
        self._rl_alerted_at: dict[tuple[str, str], float] = {}

        # Already-alerted enumeration keys (similar cooldown)
        self._enum_alerted_at: dict[tuple[str, str], float] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process(self, record: Record, now: Optional[float] = None) -> list[Alert]:
        """Process one record; return 0–2 alerts (rate-limit and/or enum)."""
        if now is None:
            now = time.time()

        alerts: list[Alert] = []
        identity = record.user or f"ip:unknown"
        norm_path = normalize_path(record.path)

        # 1. Rate-limit check
        rl_alert = self._check_rate_limit(identity, norm_path, record, now)
        if rl_alert:
            alerts.append(rl_alert)

        # 2. Enumeration / bot check
        enum_alert = self._check_enumeration(identity, norm_path, record, now)
        if enum_alert:
            alerts.append(enum_alert)

        return alerts

    def process_many(self, records: Iterable[Record]) -> list[Alert]:
        """Process an iterable of records and return all alerts."""
        alerts: list[Alert] = []
        for rec in records:
            alerts.extend(self.process(rec))
        return alerts

    # ------------------------------------------------------------------
    # Rate-limit internals
    # ------------------------------------------------------------------

    def _check_rate_limit(
        self,
        identity: str,
        norm_path: str,
        record: Record,
        now: float,
    ) -> Optional[Alert]:
        """Sliding-window check; returns an Alert when the limit is exceeded."""
        key = (identity, norm_path)
        win = self._windows.setdefault(key, _Window())

        # Evict timestamps outside the window
        cutoff = now - self.window_s
        while win.hits and win.hits[0] < cutoff:
            win.hits.popleft()

        win.hits.append(now)
        count = len(win.hits)

        if count > self.rate_limit:
            # Cooldown: only re-alert once per window to avoid alert storm
            last_alert = self._rl_alerted_at.get(key, 0.0)
            if now - last_alert < self.window_s:
                return None
            self._rl_alerted_at[key] = now

            return _make_alert(
                alert_type="RATE_LIMIT",
                severity="MEDIUM",
                user=record.user,
                endpoint=norm_path,
                object_id="",
                owasp_category="API4",
                explanation=(
                    f"'{identity}' sent {count} requests to {norm_path} "
                    f"in {self.window_s:.0f}s (limit: {self.rate_limit}). "
                    f"OWASP API4:2023 – Unrestricted Resource Consumption."
                ),
                raw_path=record.path,
                method=record.method,
                status=record.status,
                req_body=record.req_body,
                resp_body=record.resp_body,
            )
        return None

    # ------------------------------------------------------------------
    # Enumeration internals
    # ------------------------------------------------------------------

    def _check_enumeration(
        self,
        identity: str,
        norm_path: str,
        record: Record,
        now: float,
    ) -> Optional[Alert]:
        """Detect rapid sequential integer-ID scanning on the same endpoint."""
        # Only interested in endpoints that have an {id} segment
        if "{id}" not in normalize_path(record.path):
            return None

        # Extract the numeric ID from the raw path
        obj_id = _extract_numeric_id(record.path)
        if obj_id is None:
            return None

        key = (identity, norm_path)
        hits = self._enum_hits.setdefault(key, [])

        # Evict hits outside the burst window
        cutoff = now - self.enum_window_s
        hits[:] = [(ts, oid) for ts, oid in hits if ts >= cutoff]

        # Only append if this ID is new in the burst window
        seen_ids = {oid for _, oid in hits}
        if obj_id not in seen_ids:
            hits.append((now, obj_id))

        distinct_count = len({oid for _, oid in hits})

        if distinct_count >= self.enum_threshold:
            last_alert = self._enum_alerted_at.get(key, 0.0)
            if now - last_alert < self.enum_window_s:
                return None
            self._enum_alerted_at[key] = now

            return _make_alert(
                alert_type="ENUMERATION",
                severity="HIGH",
                user=record.user,
                endpoint=norm_path,
                object_id=obj_id,
                owasp_category="API6",
                explanation=(
                    f"'{identity}' accessed {distinct_count} distinct object IDs "
                    f"on {norm_path} within {self.enum_window_s:.0f}s. "
                    f"Possible ID enumeration / scraping attack. "
                    f"OWASP API6:2023 – Unrestricted Access to Sensitive Business Flows."
                ),
                raw_path=record.path,
                method=record.method,
                status=record.status,
                req_body=record.req_body,
                resp_body=record.resp_body,
            )
        return None


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _extract_numeric_id(path: str) -> Optional[str]:
    """Return the last purely-numeric path segment, or ``None``."""
    for seg in reversed(path.rstrip("/").split("/")):
        if seg.isdigit():
            return seg
    return None

