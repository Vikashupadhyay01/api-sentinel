"""
capture/proxy.py – API-Sentinel capture proxy.

Listens on :8080, forwards every request to the mock API on :8000, and
writes one JSON line per round-trip to data/events.jsonl.

Event schema
------------
  ts          ISO-8601 timestamp (UTC)
  method      HTTP verb
  path        raw request path
  query       raw query string (may be empty)
  status      upstream HTTP status code
  user        username resolved from Bearer token, or null
  req_body    request body as a string (may be empty)
  resp_body   response body as a string
  latency_ms  round-trip latency in milliseconds (float)
  blocked     true only when ENFORCE=1 and the request was denied

Enforcement mode (ENFORCE=1)
-----------------------------
Before forwarding, the proxy POSTs to the detection API (port 9000) at
/api/analyze.  If the response signals a violation, the proxy returns 403
immediately without forwarding and logs the event as blocked=true.

Usage
-----
  python capture/proxy.py
  ENFORCE=1 DETECTION_API=http://127.0.0.1:9000 python capture/proxy.py

  Or with the Flask dev server directly:
  flask --app capture.proxy run --port 8080
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
from flask import Flask, request, Response

# ---------------------------------------------------------------------------
# Configuration (all tuneable via environment variables)
# ---------------------------------------------------------------------------
UPSTREAM_URL: str = os.getenv("UPSTREAM_URL", "http://127.0.0.1:8000")
DETECTION_API: str = os.getenv("DETECTION_API", "http://127.0.0.1:9000")
EVENTS_FILE: Path = Path(os.getenv("EVENTS_FILE", "data/events.jsonl"))
ENFORCE: bool = os.getenv("ENFORCE", "0") == "1"
PORT: int = int(os.getenv("PROXY_PORT", "8080"))

# Dynamic mode cache (checks detection API every 1.0s for runtime mode toggles)
_mode_cache: dict[str, Any] = {"mode": "enforce" if ENFORCE else "passive", "last_check": 0.0}


def _is_enforce_active() -> bool:
    """Return True if enforcement mode is active (checks environment and detection API)."""
    now = time.time()
    if now - _mode_cache["last_check"] > 1.0:
        try:
            resp = httpx.get(f"{DETECTION_API}/api/mode", timeout=0.5)
            if resp.status_code == 200:
                _mode_cache["mode"] = resp.json().get("mode", "passive")
        except Exception:
            pass
        _mode_cache["last_check"] = now
    return _mode_cache["mode"] == "enforce"

# Ensure the parent directory for the event log exists
EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)

# Reuse a single httpx client for connection pooling (improves latency)
_http_client: httpx.Client = httpx.Client(
    base_url=UPSTREAM_URL,
    timeout=30.0,
    follow_redirects=True,
)

# ---------------------------------------------------------------------------
# Hop-by-hop headers that must NOT be forwarded (RFC 7230 §6.1)
# ---------------------------------------------------------------------------
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
    }
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_user(auth_header: Optional[str]) -> Optional[str]:
    """Extract username from a Bearer token header.

    Token format is ``token-<username>`` (as issued by the mock API).
    Returns None when the header is absent or the format is unexpected.
    """
    if auth_header and auth_header.startswith("Bearer token-"):
        # e.g. "Bearer token-alice" -> "alice"
        return auth_header.split("token-", 1)[1].strip()
    return None


def _write_event(event: dict) -> None:
    """Append one JSON line to the event log file.

    Using mode 'a' with an OS-level write call is atomic on POSIX for
    writes smaller than PIPE_BUF (~4 KB), which covers all our events.
    """
    line = json.dumps(event, ensure_ascii=False) + "\n"
    with EVENTS_FILE.open("a", encoding="utf-8") as fh:
        fh.write(line)


def _check_enforcement(partial_event: dict) -> Optional[dict]:
    """Ask the detection API whether this request should be blocked.

    Returns the detection response dict (with ``block`` and ``reason``
    keys) if the detection API is reachable, or None on any connectivity
    error (fail-open: when the engine is unreachable, traffic passes).
    """
    try:
        resp = httpx.post(
            f"{DETECTION_API}/api/analyze",
            json=partial_event,
            timeout=2.0,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception as exc:
        print(f"[proxy enforcement error] {exc}", flush=True)
    return None


# ---------------------------------------------------------------------------
# Catch-all reverse proxy route
# ---------------------------------------------------------------------------

@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
def proxy(path: str) -> Response:
    """Reverse-proxy every request to the upstream and log the event."""
    # Read the raw request body (empty for GET/HEAD/DELETE)
    req_body_bytes: bytes = request.get_data()
    req_body_str: str = req_body_bytes.decode("utf-8", errors="replace")

    auth_header: Optional[str] = request.headers.get("Authorization")
    user = _resolve_user(auth_header)
    query_string: str = request.query_string.decode("utf-8", errors="replace")
    full_path: str = f"/{path}"

    # Build a partial event (we fill status/resp_body/latency after upstream)
    partial_event: dict = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "method": request.method,
        "path": full_path,
        "query": query_string,
        "user": user,
        "req_body": req_body_str,
    }

    # ------------------------------------------------------------------
    # Enforcement mode: pre-flight check with the detection engine
    # ------------------------------------------------------------------
    if _is_enforce_active():
        verdict = _check_enforcement(partial_event)
        if verdict and verdict.get("block"):
            reason = verdict.get("reason", "Policy violation")
            owasp_category = verdict.get("owasp_category", "API1")
            blocked_event = {
                **partial_event,
                "status": 403,
                "resp_body": json.dumps({
                    "error": "Blocked",
                    "reason": reason,
                    "owasp_category": owasp_category,
                }),
                "latency_ms": 0.0,
                "blocked": True,
            }
            _write_event(blocked_event)
            return Response(
                json.dumps({"error": "Blocked by API-Sentinel", "reason": reason}),
                status=403,
                content_type="application/json",
            )

    # ------------------------------------------------------------------
    # Forward the request to the upstream mock API
    # ------------------------------------------------------------------
    forward_headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in _HOP_BY_HOP
    }

    # Reconstruct the full URL path with query string
    upstream_path = full_path
    if query_string:
        upstream_path = f"{full_path}?{query_string}"

    t0 = time.perf_counter()
    try:
        upstream_response = _http_client.request(
            method=request.method,
            url=upstream_path,
            headers=forward_headers,
            content=req_body_bytes,
        )
    except httpx.ConnectError as exc:
        # Upstream is unreachable – return a clear 502 to the caller
        error_event = {
            **partial_event,
            "status": 502,
            "resp_body": f"Upstream unreachable: {exc}",
            "latency_ms": 0.0,
            "blocked": False,
        }
        _write_event(error_event)
        return Response(
            json.dumps({"error": "Bad Gateway", "detail": "Upstream API is unreachable"}),
            status=502,
            content_type="application/json",
        )
    latency_ms = (time.perf_counter() - t0) * 1000.0

    resp_body_str: str = upstream_response.text

    # ------------------------------------------------------------------
    # Write the completed event
    # ------------------------------------------------------------------
    event: dict = {
        **partial_event,
        "status": upstream_response.status_code,
        "resp_body": resp_body_str,
        "latency_ms": round(latency_ms, 3),
        "blocked": False,
    }
    _write_event(event)

    # ------------------------------------------------------------------
    # Return the upstream response to the original caller
    # ------------------------------------------------------------------
    # Strip hop-by-hop and content-encoding from upstream response headers
    # (Flask will handle encoding itself)
    response_headers = {
        k: v
        for k, v in upstream_response.headers.items()
        if k.lower() not in _HOP_BY_HOP
        and k.lower() not in ("content-length", "content-encoding")
    }

    return Response(
        response=upstream_response.content,
        status=upstream_response.status_code,
        headers=response_headers,
        content_type=upstream_response.headers.get("content-type", "application/json"),
    )


# ---------------------------------------------------------------------------
# Entry point (run directly: python capture/proxy.py)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    enforce_msg = " [ENFORCE=1 mode: violations will be blocked]" if ENFORCE else ""
    print(f"API-Sentinel Capture Proxy{enforce_msg}")
    print(f"  Listening : http://127.0.0.1:{PORT}")
    print(f"  Upstream  : {UPSTREAM_URL}")
    print(f"  Event log : {EVENTS_FILE.resolve()}")
    print()
    app.run(host="127.0.0.1", port=PORT, threaded=True, debug=False)
