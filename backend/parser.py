"""
backend/parser.py – JSONL event log reader.

Reads the event log written by capture/proxy.py and yields typed Record
dataclass instances.  Malformed lines are silently skipped so a corrupt
line never crashes the pipeline.

Usage
-----
  from backend.parser import Record, iter_records

  for record in iter_records("data/events.jsonl"):
      print(record.user, record.path, record.status)
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Generator, Optional


# ---------------------------------------------------------------------------
# Record dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Record:
    """A single captured HTTP request/response pair.

    Fields mirror the JSONL schema written by the capture proxy.

    Attributes
    ----------
    ts:
        UTC ISO-8601 timestamp string.
    method:
        HTTP verb in uppercase (``"GET"``, ``"POST"``, …).
    path:
        Raw request path including leading slash (``"/api/v1/orders/101"``).
    query:
        Raw query string without leading ``?`` (may be empty).
    status:
        HTTP response status code returned by the upstream.
    user:
        Username resolved from the Bearer token (e.g. ``"alice"``), or
        ``None`` when the request was unauthenticated.
    req_body:
        Request body decoded to string (may be empty).
    resp_body:
        Response body decoded to string.
    latency_ms:
        Round-trip latency in milliseconds.
    blocked:
        ``True`` when enforcement mode blocked the request.
    """

    ts: str
    method: str
    path: str
    query: str
    status: int
    user: Optional[str]
    req_body: str
    resp_body: str
    latency_ms: float
    blocked: bool = False

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    @property
    def datetime(self) -> Optional[datetime]:
        """Parse ``ts`` into a timezone-aware :class:`datetime`, or ``None``."""
        try:
            return datetime.fromisoformat(self.ts)
        except (ValueError, TypeError):
            return None

    @property
    def resp_json(self) -> Optional[object]:
        """Attempt to parse ``resp_body`` as JSON; ``None`` on failure."""
        try:
            return json.loads(self.resp_body)
        except (json.JSONDecodeError, TypeError):
            return None

    @property
    def req_json(self) -> Optional[object]:
        """Attempt to parse ``req_body`` as JSON; ``None`` on failure."""
        try:
            return json.loads(self.req_body)
        except (json.JSONDecodeError, TypeError):
            return None


# ---------------------------------------------------------------------------
# Fields required in every valid event line
# ---------------------------------------------------------------------------
_REQUIRED_FIELDS: frozenset[str] = frozenset(
    {"ts", "method", "path", "query", "status", "user",
     "req_body", "resp_body", "latency_ms"}
)


def parse_line(line: str) -> Optional[Record]:
    """Parse a single JSONL event line into a :class:`Record`.

    Returns ``None`` for blank lines, JSON errors, missing fields, or
    type-coercion failures — all callers should treat ``None`` as "skip".
    """
    line = line.strip()
    if not line:
        return None

    try:
        data: dict = json.loads(line)
    except json.JSONDecodeError:
        return None

    if not isinstance(data, dict):
        return None

    if not _REQUIRED_FIELDS.issubset(data.keys()):
        return None

    try:
        return Record(
            ts=str(data["ts"]),
            method=str(data["method"]).upper(),
            path=str(data["path"]),
            query=str(data.get("query", "")),
            status=int(data["status"]),
            user=data["user"] if data["user"] is not None else None,
            req_body=str(data.get("req_body", "")),
            resp_body=str(data.get("resp_body", "")),
            latency_ms=float(data["latency_ms"]),
            blocked=bool(data.get("blocked", False)),
        )
    except (ValueError, TypeError, KeyError):
        return None


def iter_records(
    path: str | Path,
    *,
    warn_on_malformed: bool = False,
) -> Generator[Record, None, None]:
    """Yield :class:`Record` objects from a JSONL event log file.

    Parameters
    ----------
    path:
        Path to the JSONL event log (e.g. ``"data/events.jsonl"``).
    warn_on_malformed:
        When ``True``, print a warning to *stderr* for each bad line.

    Yields
    ------
    Record
        One record per valid JSONL line.

    Notes
    -----
    The file is opened with ``errors="replace"`` so binary garbage never
    raises ``UnicodeDecodeError``.  Non-existent files yield nothing.
    """
    path = Path(path)
    if not path.exists():
        return

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for lineno, raw_line in enumerate(fh, start=1):
            record = parse_line(raw_line)
            if record is None:
                if warn_on_malformed and raw_line.strip():
                    print(
                        f"[parser] WARNING: malformed line {lineno} in {path}",
                        file=sys.stderr,
                    )
                continue
            yield record


def load_records(path: str | Path) -> list[Record]:
    """Load all valid records from *path* into a list (convenience wrapper)."""
    return list(iter_records(path))

