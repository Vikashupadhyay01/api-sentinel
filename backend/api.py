"""
backend/api.py – Detection API service for API-Sentinel.

Listens on port 9000.  Provides CORS-enabled endpoints consumed by:
  - The React dashboard on port 5173
  - The capture proxy on port 8080 (enforcement mode pre-flight check)

Endpoints
---------
  GET  /api/health      – simple health check {"status": "ok"}
  GET  /api/endpoints   – full endpoint inventory with classification & stats
  GET  /api/alerts      – list of all emitted alerts (newest first, PII-masked)
  GET  /api/stats       – high-level summary counters + OWASP category breakdown
  POST /api/analyze     – enforcement check called by proxy before forwarding;
                          evaluates BOLA & rate-limit, returns {"block": bool, "reason": str}

Usage
-----
  python -m backend.api
  python backend/api.py
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any

# Ensure repo root is in sys.path so backend imports work when run directly
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from flask import Flask, jsonify, request, Response

from backend.demo_helper import run_demo_attack
from backend.discovery import inventory_to_list, normalize_path
from backend.export import (
    export_alerts_csv,
    export_alerts_json,
    export_blocked_csv,
    export_discovered_openapi,
)
from backend.parser import Record, parse_line
from backend.pii import mask, mask_alert
from backend.pipeline import GLOBAL_STATE, Pipeline
from backend.report import generate_security_report_pdf

PORT = int(os.getenv("DETECTION_API_PORT", "9000"))
SPEC_PATH = os.getenv("OPENAPI_SPEC", "openapi/openapi.yaml")
EVENTS_FILE = os.getenv("EVENTS_FILE", "data/events.jsonl")

app = Flask(__name__)

# Single Pipeline instance that shares GLOBAL_STATE
_pipeline = Pipeline(spec_path=SPEC_PATH, state=GLOBAL_STATE)


# ---------------------------------------------------------------------------
# Manual CORS headers (limited to http://localhost:5173)
# ---------------------------------------------------------------------------

ALLOWED_ORIGINS = {"http://localhost:5173", "http://127.0.0.1:5173"}


@app.after_request
def _add_cors_headers(response: Response) -> Response:
    """Allow cross-origin requests from the React dashboard (port 5173)."""
    origin = request.headers.get("Origin")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
    else:
        response.headers["Access-Control-Allow-Origin"] = "http://localhost:5173"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health():
    """Simple health probe."""
    return jsonify({
        "status": "ok",
        "service": "api-sentinel-detection-api",
        "version": "1.0",
    })


# ---------------------------------------------------------------------------
# Inventory endpoint
# ---------------------------------------------------------------------------

@app.route("/api/endpoints", methods=["GET"])
def get_endpoints():
    """Return the full observed endpoint inventory with classifications."""
    with GLOBAL_STATE.lock:
        inventory_list = inventory_to_list(GLOBAL_STATE.inventory)
    return jsonify(inventory_list)


# ---------------------------------------------------------------------------
# Alerts endpoint
# ---------------------------------------------------------------------------

@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    """Return all alerts (newest first), with PII already masked."""
    with GLOBAL_STATE.lock:
        # Return a copy, reversed so latest alerts appear first
        alerts_copy = list(reversed(GLOBAL_STATE.alerts))
    return jsonify(alerts_copy)


# ---------------------------------------------------------------------------
# Blocked requests endpoint (One shared source of truth with stats)
# ---------------------------------------------------------------------------

@app.route("/api/blocked", methods=["GET"])
def get_blocked():
    """Return all blocked requests (newest first), with PII already masked."""
    with GLOBAL_STATE.lock:
        blocked_copy = list(reversed(GLOBAL_STATE.blocked_requests))
    return jsonify(blocked_copy)


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------

@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Return dashboard summary metrics and OWASP category breakdown."""
    return jsonify(GLOBAL_STATE.to_stats())


# ---------------------------------------------------------------------------
# Timeline endpoint (15-min requests/alerts/blocked in 10s intervals)
# ---------------------------------------------------------------------------

@app.route("/api/timeline", methods=["GET"])
def get_timeline():
    """Return 15-minute rolling time-series in 10-second buckets."""
    with GLOBAL_STATE.lock:
        buckets = GLOBAL_STATE.timeline.get_buckets()
    return jsonify({
        "interval_seconds": 10,
        "window_minutes": 15,
        "buckets": buckets,
    })


# ---------------------------------------------------------------------------
# Top users endpoint
# ---------------------------------------------------------------------------

@app.route("/api/top-users", methods=["GET"])
def get_top_users():
    """Return ranking of users by alerts and threats."""
    with GLOBAL_STATE.lock:
        from backend.users import compute_top_users
        users = compute_top_users(GLOBAL_STATE.alerts, GLOBAL_STATE.blocked_requests)
    return jsonify(users)


# ---------------------------------------------------------------------------
# PDF Report Endpoint
# ---------------------------------------------------------------------------

@app.route("/api/report.pdf", methods=["GET"])
def get_pdf_report():
    """Generate and download executive PDF security assessment report."""
    stats_data = GLOBAL_STATE.to_stats()
    with GLOBAL_STATE.lock:
        inv_copy = dict(GLOBAL_STATE.inventory)
        alerts_copy = list(reversed(GLOBAL_STATE.alerts))
        blocked_copy = list(reversed(GLOBAL_STATE.blocked_requests))

    pdf_bytes = generate_security_report_pdf(
        stats=stats_data,
        inventory=inv_copy,
        alerts=alerts_copy,
        blocked_requests=blocked_copy,
    )
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": "attachment; filename=api-sentinel-security-report.pdf"
        },
    )


# ---------------------------------------------------------------------------
# Data Export Endpoints (CSV, JSON, Discovered OpenAPI Contract)
# ---------------------------------------------------------------------------

@app.route("/api/export/alerts.csv", methods=["GET"])
def export_alerts_csv_endpoint():
    """Export all alerts in CSV format with PII masked."""
    with GLOBAL_STATE.lock:
        csv_data = export_alerts_csv(GLOBAL_STATE.alerts)
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=api-sentinel-alerts.csv"},
    )


@app.route("/api/export/alerts.json", methods=["GET"])
def export_alerts_json_endpoint():
    """Export all alerts in JSON format with PII masked."""
    with GLOBAL_STATE.lock:
        json_data = export_alerts_json(GLOBAL_STATE.alerts)
    return Response(
        json_data,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=api-sentinel-alerts.json"},
    )


@app.route("/api/export/blocked.csv", methods=["GET"])
def export_blocked_csv_endpoint():
    """Export all blocked requests in CSV format with PII masked."""
    with GLOBAL_STATE.lock:
        csv_data = export_blocked_csv(GLOBAL_STATE.blocked_requests)
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=api-sentinel-blocked.csv"},
    )


@app.route("/api/export/openapi.yaml", methods=["GET"])
def export_openapi_yaml_endpoint():
    """Export observed OpenAPI spec tagged with x-sentinel-status (shadow/zombie)."""
    with GLOBAL_STATE.lock:
        yaml_data = export_discovered_openapi(GLOBAL_STATE.inventory, SPEC_PATH)
    return Response(
        yaml_data,
        mimetype="application/x-yaml",
        headers={"Content-Disposition": "attachment; filename=openapi-discovered.yaml"},
    )


# ---------------------------------------------------------------------------
# Mode Toggle Endpoint (Dynamic Passive / Enforce)
# ---------------------------------------------------------------------------

@app.route("/api/mode", methods=["GET", "POST", "OPTIONS"])
def handle_mode():
    """Query or dynamically toggle enforcement mode at runtime."""
    if request.method == "OPTIONS":
        return "", 204

    if request.method == "POST":
        body = request.get_json(force=True, silent=True) or {}
        new_mode = str(body.get("mode", "")).lower().strip()
        if new_mode not in ("passive", "enforce"):
            return jsonify({"error": "Invalid mode. Must be 'passive' or 'enforce'."}), 400
        with GLOBAL_STATE.lock:
            GLOBAL_STATE.mode = new_mode
        return jsonify({"status": "updated", "mode": GLOBAL_STATE.mode})

    return jsonify({"mode": GLOBAL_STATE.mode})


# ---------------------------------------------------------------------------
# Demo Helper Endpoints (Attack Simulation & State Reset)
# ---------------------------------------------------------------------------

@app.route("/api/demo/attack", methods=["POST", "OPTIONS"])
def demo_attack():
    """Trigger simulated attacks strictly against local capture proxy."""
    if request.method == "OPTIONS":
        return "", 204

    body = request.get_json(force=True, silent=True) or {}
    attack_type = str(body.get("type", "all")).lower().strip()
    target = str(body.get("target", "http://127.0.0.1:8080")).strip()

    try:
        result = run_demo_attack(attack_type=attack_type, target=target)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Attack execution failed: {e}"}), 500


@app.route("/api/demo/reset", methods=["POST", "OPTIONS"])
def demo_reset():
    """Reset all in-memory detection engine state and truncate event log."""
    if request.method == "OPTIONS":
        return "", 204

    _pipeline.reset(truncate_events=True, events_path=EVENTS_FILE)
    return jsonify({
        "status": "ok",
        "message": "Demo state, detector learning, and event logs have been reset.",
    })


# ---------------------------------------------------------------------------
# Enforcement check endpoint (used by capture proxy before forwarding)
# ---------------------------------------------------------------------------

@app.route("/api/analyze", methods=["POST", "OPTIONS"])
def analyze():
    """Pre-flight security check called by the capture proxy in enforcement mode.

    Evaluates whether the incoming request should be BLOCKED before reaching
    the upstream mock API.

    Request payload (partial event):
      {
        "method": "GET",
        "path": "/api/v1/orders/201",
        "user": "alice",
        "query": "",
        "req_body": ""
      }

    Response:
      {"block": true,  "reason": "BOLA: Alice accessing Bob's order"}
      or
      {"block": false, "reason": "OK"}
    """
    if request.method == "OPTIONS":
        return "", 204

    body = request.get_json(force=True, silent=True) or {}

    method = str(body.get("method", "GET")).upper()
    path = str(body.get("path", "/"))
    user = body.get("user")
    norm_path = normalize_path(path)

    # 1. BOLA pre-flight check
    # If the user is authenticated and hitting a detail endpoint, check ownership
    if user and method == "GET" and "{id}" in norm_path:
        obj_id = _pipeline.bola_detector._extract_path_id if hasattr(_pipeline.bola_detector, "_extract_path_id") else None
        # Extract numeric id from path
        segments = path.rstrip("/").split("/")
        numeric_id = next((s for s in reversed(segments) if s.isdigit()), None)

        if numeric_id:
            known_owner = _pipeline.bola_detector._ownership.get(numeric_id)
            user_own_ids = _pipeline.bola_detector._user_ids.get(user, set())

            if known_owner is not None and known_owner != user:
                return jsonify({
                    "block": True,
                    "reason": (
                        f"BOLA violation: user '{user}' cannot access object "
                        f"{numeric_id} owned by '{known_owner}' (OWASP API1)"
                    ),
                    "owasp_category": "API1",
                })
            if known_owner is None and user in user_own_ids and numeric_id not in user_own_ids:
                return jsonify({
                    "block": True,
                    "reason": (
                        f"BOLA violation: object {numeric_id} was never seen in user '{user}' history (OWASP API1)"
                    ),
                    "owasp_category": "API1",
                })

    # 2. Rate-limit pre-flight check
    # Check sliding window count for this identity
    identity = user or "ip:unknown"
    key = (identity, norm_path)
    win = _pipeline.rate_limit_detector._windows.get(key)
    if win and len(win.hits) >= _pipeline.rate_limit_detector.rate_limit:
        return jsonify({
            "block": True,
            "reason": (
                f"Rate limit exceeded: user '{identity}' on {norm_path} "
                f"(OWASP API4)"
            ),
            "owasp_category": "API4",
        })

    # Default: allow request through
    return jsonify({"block": False, "reason": "OK"})


# ---------------------------------------------------------------------------
# Background log tailer thread
# ---------------------------------------------------------------------------

def _start_background_tailer() -> None:
    """Start a daemon thread that continuously tails data/events.jsonl from line 0."""
    def _tail_worker() -> None:
        events_path = Path(EVENTS_FILE)
        events_path.parent.mkdir(parents=True, exist_ok=True)
        # Ensure file exists
        if not events_path.exists():
            events_path.touch()

        with events_path.open("r", encoding="utf-8", errors="replace") as fh:
            while True:
                line = fh.readline()
                if line:
                    rec = parse_line(line)
                    if rec:
                        _pipeline.process_record(rec)
                else:
                    time.sleep(0.1)

    t = threading.Thread(target=_tail_worker, daemon=True)
    t.start()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"API-Sentinel Detection API listening on http://127.0.0.1:{PORT}")
    print(f"  Spec  : {SPEC_PATH}")
    print(f"  Events: {EVENTS_FILE}")
    print()

    # Pre-populate state from any events already on disk
    if Path(EVENTS_FILE).exists():
        count = _pipeline.process_file(EVENTS_FILE)
        print(f"[api] Loaded {count} historical events from {EVENTS_FILE}")

    # Start the live background tailer thread
    _start_background_tailer()

    app.run(host="127.0.0.1", port=PORT, threaded=True, debug=False)
