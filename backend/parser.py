"""Week 1 - M3 Parser (Arijeet Sharma / Chris301-droid) - MERGED v3
Rebuild HTTP request/response pairs from captured traffic.

HOW THIS FILE WAS BUILT (10 Nov 2026, ~20:55 IST):
  - Part 1 is main's backend/parser.py VERBATIM, as fetched live from
    https://raw.githubusercontent.com/Vikashupadhyay01/api-sentinel/main/backend/parser.py
    (commit ffdcd2e, 10 Nov 09:17 IST). Its Record, parse_line, iter_records
    and load_records are UNCHANGED - do not edit them.
  - Part 2 (added by M3) is the Week 1 raw-bytes parser: parse_request /
    parse_response / pair_events, plus record_to_event() which converts
    main's Record into the same ApiEvent the raw parser produces.
  - This replaces parser-v2-merge-ready.py - DO NOT USE v2. Its Record
    (timestamp, user_id, source_ip, headers, request_body, response_body)
    does NOT match main's Record (ts, method, path, query, status, user,
    req_body, resp_body, latency_ms, blocked). Pasting v2 would break
    main's design. v3 keeps main's Record exactly.

PUSH STEPS (GitHub website, tonight before midnight, 10 Nov):
  1. Open https://github.com/Vikashupadhyay01/api-sentinel, logged in as
     Chris301-droid, branch m3-parser. Use "Update branch" / "Compare" to
     pull main into m3-parser first, so this file lands on top of main.
  2. Open backend/parser.py on m3-parser, delete its TODO-stub content,
     paste this WHOLE file.
  3. Commit message: Week 1: Implement parser to rebuild HTTP request/response pairs
     Select "Commit directly to the m3-parser branch". Never commit to main.
     Do not touch discovery.py.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Generator, Optional


# ---------------------------------------------------------------------------
# PART 1 - main's JSONL event log reader (VERBATIM, do not edit)
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
    """Yield :class:`Record` objects from a JSONL event log file."""

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


# ---------------------------------------------------------------------------
# PART 2 - M3 Week 1 raw-bytes parser (ADDED, main's code above untouched)
# Parses raw HTTP request/response bytes (eBPF sniffer / mitmproxy fallback)
# into the same ApiEvent shape, so Week 2 discovery.py can use either input.
# ---------------------------------------------------------------------------

from dataclasses import field
from datetime import timezone
from typing import Dict, Union
from urllib.parse import parse_qs, urlparse


@dataclass
class HttpRequest:
    method: str
    path: str
    query: Dict[str, list] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    json_body: Optional[dict] = None
    user_id: Optional[str] = None

    @property
    def endpoint(self) -> str:
        """Normalized path for discovery, e.g. /api/v1/orders/101 -> /api/v1/orders/{id}"""
        parts = []
        for seg in self.path.split("/"):
            if seg.isdigit():
                parts.append("{id}")
            else:
                parts.append(seg)
        return "/".join(parts)


@dataclass
class HttpResponse:
    status: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    json_body: Optional[dict] = None


@dataclass
class ApiEvent:
    timestamp: str
    request: HttpRequest
    response: Optional[HttpResponse] = None
    source_ip: str = "127.0.0.1"


def _parse_headers(lines):
    headers = {}
    for line in lines:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return headers


def _try_json(body: bytes):
    try:
        return json.loads(body.decode("utf-8")) if body else None
    except Exception:
        return None


def parse_request(raw: bytes) -> HttpRequest:
    """Parse raw HTTP request bytes into HttpRequest."""
    head, _, body = raw.partition(b"\r\n\r\n")
    if not head:
        head, _, body = raw.partition(b"\n\n")
    lines = head.decode("utf-8", errors="ignore").splitlines()
    if not lines:
        raise ValueError("empty request")
    method, full_path, _ = lines[0].split(" ", 2)
    parsed = urlparse(full_path)
    headers = _parse_headers(lines[1:])
    user_id = headers.get("x-user-id")
    auth = headers.get("authorization", "")
    if not user_id and auth.startswith("Bearer "):
        user_id = auth.replace("Bearer ", "").strip() or None
    return HttpRequest(
        method=method.upper(),
        path=parsed.path,
        query=parse_qs(parsed.query),
        headers=headers,
        body=body,
        json_body=_try_json(body),
        user_id=user_id,
    )


def parse_response(raw: bytes) -> HttpResponse:
    """Parse raw HTTP response bytes into HttpResponse."""
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("utf-8", errors="ignore").splitlines()
    if not lines:
        raise ValueError("empty response")
    parts = lines[0].split(" ", 2)
    status = int(parts[1]) if len(parts) > 1 else 0
    return HttpResponse(
        status=status,
        headers=_parse_headers(lines[1:]),
        body=body,
        json_body=_try_json(body),
    )


def pair_events(req_raw: bytes, resp_raw: bytes, source_ip="127.0.0.1") -> ApiEvent:
    """Combine one request + response into a single ApiEvent for discovery/BOLA."""
    return ApiEvent(
        timestamp=datetime.now(timezone.utc).isoformat(),
        request=parse_request(req_raw),
        response=parse_response(resp_raw),
        source_ip=source_ip,
    )


def record_to_event(record: Record) -> ApiEvent:
    """Convert main's JSONL Record into the ApiEvent the raw parser produces.

    Field mapping (main's schema -> ApiEvent):
      ts -> timestamp | user -> user_id | query (raw string) -> parse_qs
      req_body (string) -> json_body via Record.req_json
      resp_body (string) -> json_body via Record.resp_json
    Main's schema has no source_ip, so it defaults to 127.0.0.1.
    """
    req_json = record.req_json
    resp_json = record.resp_json
    return ApiEvent(
        timestamp=record.ts,
        request=HttpRequest(
            method=record.method,
            path=record.path,
            query=parse_qs(record.query),
            json_body=req_json if isinstance(req_json, dict) else None,
            user_id=record.user,
        ),
        response=HttpResponse(
            status=record.status,
            json_body=resp_json if isinstance(resp_json, dict) else None,
        ),
        source_ip="127.0.0.1",
    )


if __name__ == "__main__":
    # Self-test 1: main's JSONL path, using main's exact schema
    line = json.dumps({
        "ts": "2026-11-10T10:00:00+00:00",
        "method": "GET", "path": "/api/v1/orders/101", "query": "",
        "status": 200, "user": "alice",
        "req_body": "", "resp_body": '{"order_id": 101, "user_id": "alice"}',
        "latency_ms": 12.5, "blocked": False,
    })
    rec = parse_line(line)
    assert rec is not None and rec.user == "alice" and rec.status == 200
    assert rec.resp_json == {"order_id": 101, "user_id": "alice"}
    assert parse_line('{"bad": 1}') is None  # missing required fields -> skip
    ev = record_to_event(rec)
    assert ev.request.endpoint == "/api/v1/orders/{id}"
    assert ev.request.user_id == "alice" and ev.response.status == 200
    print(f"JSONL: {ev.request.method} {ev.request.path} -> {ev.request.endpoint} -> {ev.response.status} user={ev.request.user_id}")

    # Self-test 2: raw-bytes path (Week 1 original)
    raw_req = b"GET /api/v1/orders/101 HTTP/1.1\r\nHost: localhost:8000\r\nX-User-Id: user-1\r\n\r\n"
    raw_resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"order_id\": 101, \"user_id\": \"user-1\"}"
    ev2 = pair_events(raw_req, raw_resp)
    assert ev2.request.endpoint == "/api/v1/orders/{id}"
    assert ev2.response.status == 200 and ev2.request.user_id == "user-1"
    print(f"RAW: {ev2.request.method} {ev2.request.path} -> {ev2.request.endpoint} -> {ev2.response.status} user={ev2.request.user_id}")

    # Self-test 3: iter_records over a temp JSONL file
    import tempfile, os
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as fh:
        fh.write(line + "\n")
        fh.write('{"bad": 1}\n')
        fh.write("\n")
        tmp = fh.name
    try:
        assert len(load_records(tmp)) == 1
    finally:
        os.unlink(tmp)
    print("parser v3 self-test OK (main JSONL + raw-bytes + bridge)")
