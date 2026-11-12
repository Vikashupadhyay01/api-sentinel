"""
backend/pipeline.py – Live event log consumer and detection pipeline.

Runs as a background daemon or standalone command:
  python -m backend.pipeline
  python -m backend.pipeline --events data/events.jsonl --tail

Architecture
------------
The Pipeline maintains in-memory state shared with the detection API:
  - ``inventory``      – mapping of (method, norm_path) → EndpointInfo
  - ``alerts``         – ordered list of Alert objects
  - ``blocked_events`` – count and records of requests blocked by enforcement
  - ``stats``          – summary counters (total requests, alerts, blocked)

Detectors fed by the pipeline:
  1. Discovery     – build/update endpoint inventory (Shadow / Zombie)
  2. BOLA          – check cross-user object access
  3. RateLimit/Bot – check sliding-window rate and sequential ID scanning

All alert explanations and event bodies are run through ``mask()`` before
storage so no raw PII ever enters the API response layer.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Ensure repo root is in sys.path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from backend.bola import Alert, BOLADetector
from backend.discovery import (
    DEFAULT_IGNORE_PATTERNS,
    EndpointInfo,
    build_inventory,
    classify,
    is_inventory_candidate,
    load_openapi,
    normalize_path,
    OWASP_CATEGORY,
)
from backend.parser import Record, parse_line
from backend.pii import mask, mask_alert
from backend.ratelimit import RateLimitDetector
from backend.remediation import get_owasp_description, get_remediation
from backend.risk import compute_risk_score
from backend.timeline import TimelineTracker
from backend.users import compute_top_users


def _extract_path_id(path: str) -> Optional[str]:
    """Extract numeric ID from path if present (e.g. /orders/201 -> '201')."""
    for seg in reversed(path.rstrip("/").split("/")):
        if seg.isdigit():
            return seg
    return None


# ---------------------------------------------------------------------------
# Global shared state (thread-safe, read by detection API)
# ---------------------------------------------------------------------------

@dataclass
class PipelineState:
    """Thread-safe container for all detection engine state."""
    lock: threading.RLock = field(default_factory=threading.RLock)
    inventory: dict[tuple[str, str], EndpointInfo] = field(default_factory=dict)
    alerts: list[dict] = field(default_factory=list)
    blocked_requests: list[dict] = field(default_factory=list)
    total_requests: int = 0
    documented_endpoints: set[tuple[str, str]] = field(default_factory=set)
    timeline: TimelineTracker = field(default_factory=TimelineTracker)
    mode: str = field(default_factory=lambda: "enforce" if os.getenv("ENFORCE", "0") == "1" else "passive")

    @property
    def blocked_count(self) -> int:
        return len(self.blocked_requests)

    def reset(self) -> None:
        """Clear all in-memory events, alerts, inventory, and timeline metrics."""
        with self.lock:
            self.inventory.clear()
            self.alerts.clear()
            self.blocked_requests.clear()
            self.total_requests = 0
            self.timeline.clear()

    def to_stats(self) -> dict:
        """Return a snapshot of current stats for GET /api/stats."""
        with self.lock:
            shadow_count = sum(
                1 for e in self.inventory.values() if e.classification == "shadow"
            )
            zombie_count = sum(
                1 for e in self.inventory.values() if e.classification == "zombie"
            )
            documented_count = sum(
                1 for e in self.inventory.values() if e.classification == "documented"
            )

            # Alerts broken down by OWASP category
            owasp_breakdown: dict[str, int] = {}
            for a in self.alerts:
                cat = a.get("owasp_category", "UNKNOWN")
                owasp_breakdown[cat] = owasp_breakdown.get(cat, 0) + 1

            # Compute risk score (0-100) and severity rating
            risk = compute_risk_score(
                alerts=self.alerts,
                shadow_count=shadow_count,
                zombie_count=zombie_count,
                blocked_count=len(self.blocked_requests),
            )

            # Compute top users by alert / threat count
            top_users = compute_top_users(
                alerts=self.alerts,
                blocked_requests=self.blocked_requests,
                limit=10,
            )

            return {
                "mode": self.mode,
                "total_requests": self.total_requests,
                "total_endpoints": len(self.inventory),
                "documented_endpoints": documented_count,
                "shadow_endpoints": shadow_count,
                "zombie_endpoints": zombie_count,
                "total_alerts": len(self.alerts),
                "blocked_requests": len(self.blocked_requests),
                "owasp_breakdown": owasp_breakdown,
                "risk_score": risk["score"],
                "risk_level": risk["level"],
                "risk_color": risk["color"],
                "risk_breakdown": risk["breakdown"],
                "top_users": top_users,
            }


# Singleton pipeline state instance
GLOBAL_STATE = PipelineState()


# ---------------------------------------------------------------------------
# Pipeline class
# ---------------------------------------------------------------------------

class Pipeline:
    """Consumes Records and feeds the detector suite."""

    def __init__(
        self,
        spec_path: str | Path = "openapi/openapi.yaml",
        state: Optional[PipelineState] = None,
        ignore_patterns: Optional[list[str]] = None,
    ) -> None:
        self.spec_path = Path(spec_path)
        self.state = state or GLOBAL_STATE
        self.ignore_patterns = ignore_patterns

        # Load documented contract
        self.state.documented_endpoints = load_openapi(self.spec_path)

        # Detectors
        self.bola_detector = BOLADetector()
        self.rate_limit_detector = RateLimitDetector()

    def reset(self, truncate_events: bool = False, events_path: str | Path | None = None) -> None:
        """Reset in-memory state and all detector learning/windows."""
        self.state.reset()
        self.bola_detector._ownership.clear()
        self.bola_detector._user_ids.clear()
        self.bola_detector._alerted.clear()
        self.rate_limit_detector._windows.clear()
        self.rate_limit_detector._enum_hits.clear()
        self.rate_limit_detector._rl_alerted_at.clear()
        self.rate_limit_detector._enum_alerted_at.clear()
        if truncate_events and events_path:
            p = Path(events_path)
            if p.exists():
                p.write_text("", encoding="utf-8")

    def process_record(self, record: Record) -> list[dict]:
        """Process one Record through all detectors.

        Returns any new alerts generated by this record.
        """
        new_alerts: list[dict] = []

        with self.state.lock:
            self.state.total_requests += 1
            self.state.timeline.record_request(record.ts)

            # ----------------------------------------------------------
            # Blocked request recording (One shared source of truth)
            # ----------------------------------------------------------
            if record.blocked or record.status == 403:
                self.state.timeline.record_blocked(record.ts)
                obj_id = _extract_path_id(record.path) or ""
                reason = "Blocked by API-Sentinel enforcement"
                owasp_cat = "API1" if "{id}" in normalize_path(record.path) else "API4"

                # Parse response body if JSON to extract reason and category
                if record.resp_body:
                    try:
                        resp_data = json.loads(record.resp_body)
                        if isinstance(resp_data, dict):
                            if "reason" in resp_data:
                                reason = str(resp_data["reason"])
                            elif "error" in resp_data:
                                reason = str(resp_data["error"])
                            if "owasp_category" in resp_data:
                                owasp_cat = str(resp_data["owasp_category"])
                            elif "API1" in reason or "BOLA" in reason:
                                owasp_cat = "API1"
                            elif "API4" in reason or "rate limit" in reason.lower():
                                owasp_cat = "API4"
                            elif "API6" in reason or "enumeration" in reason.lower():
                                owasp_cat = "API6"
                    except Exception:
                        pass

                blocked_entry = {
                    "id": f"blocked-{len(self.state.blocked_requests) + 1}",
                    "ts": record.ts,
                    "time": record.ts,
                    "user": record.user or "anonymous",
                    "method": record.method,
                    "path": record.path,
                    "object_id": obj_id,
                    "reason": mask(reason),
                    "owasp_category": owasp_cat,
                    "status": record.status if record.status else 403,
                }
                self.state.blocked_requests.append(blocked_entry)

            # ----------------------------------------------------------
            # 1. Discovery / Inventory update (Filter noise)
            # ----------------------------------------------------------
            if is_inventory_candidate(record.path, self.ignore_patterns):
                norm_path = normalize_path(record.path)
                key = (record.method, norm_path)

                if key not in self.state.inventory:
                    cls = classify(
                        record.method,
                        norm_path,
                        self.state.documented_endpoints,
                    )
                    self.state.inventory[key] = EndpointInfo(
                        method=record.method,
                        norm_path=norm_path,
                        classification=cls,
                        owasp_category=OWASP_CATEGORY[cls],
                    )

                    # Emit an alert immediately when a Shadow or Zombie API is first discovered
                    if cls in ("shadow", "zombie"):
                        severity = "HIGH" if cls == "zombie" else "MEDIUM"
                        shadow_alert = {
                            "id": f"{cls}-{record.method}-{norm_path}".replace("/", "-"),
                            "ts": record.ts,
                            "type": cls.upper(),
                            "severity": severity,
                            "user": record.user,
                            "endpoint": norm_path,
                            "object_id": "",
                            "owasp_category": "API9",
                            "explanation": mask(
                                f"{cls.capitalize()} API observed: {record.method} {norm_path}. "
                                f"OWASP API9:2023 – Improper Inventory Management."
                            ),
                            "raw_path": record.path,
                            "method": record.method,
                            "status": record.status,
                            "req_body": mask(record.req_body) if record.req_body else "",
                            "resp_body": mask(record.resp_body) if record.resp_body else "",
                            "remediation": get_remediation("API9"),
                            "owasp_description": get_owasp_description("API9"),
                        }
                        self.state.alerts.append(shadow_alert)
                        new_alerts.append(shadow_alert)
                        self.state.timeline.record_alert(shadow_alert["ts"])

                info = self.state.inventory[key]
                info.hit_count += 1
                info.last_seen = record.ts
                if info.first_seen is None:
                    info.first_seen = record.ts
                info.status_codes[record.status] = (
                    info.status_codes.get(record.status, 0) + 1
                )
                if record.user:
                    info.users_seen.add(record.user)

        # ----------------------------------------------------------
        # 2. BOLA detection
        # ----------------------------------------------------------
        bola_alert = self.bola_detector.process(record)
        if bola_alert:
            alert_dict = mask_alert(bola_alert.to_dict())
            with self.state.lock:
                self.state.alerts.append(alert_dict)
                self.state.timeline.record_alert(alert_dict.get("ts"))
            new_alerts.append(alert_dict)

        # ----------------------------------------------------------
        # 3. Rate-limit & Enumeration detection
        # ----------------------------------------------------------
        rl_alerts = self.rate_limit_detector.process(record)
        for alert in rl_alerts:
            alert_dict = mask_alert(alert.to_dict())
            with self.state.lock:
                self.state.alerts.append(alert_dict)
                self.state.timeline.record_alert(alert_dict.get("ts"))
            new_alerts.append(alert_dict)

        return new_alerts

    def process_file(self, events_path: str | Path) -> int:
        """Read all existing records from *events_path* and process them.

        Returns the number of records processed.
        """
        events_path = Path(events_path)
        if not events_path.exists():
            return 0

        count = 0
        with events_path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                rec = parse_line(line)
                if rec:
                    self.process_record(rec)
                    count += 1
        return count

    def tail(self, events_path: str | Path, poll_interval: float = 0.2) -> None:
        """Continuously tail *events_path* and process new lines as they arrive.

        Runs until interrupted (e.g. KeyboardInterrupt).
        """
        events_path = Path(events_path)
        events_path.parent.mkdir(parents=True, exist_ok=True)
        if not events_path.exists():
            events_path.touch()

        # First pass: read what is already there
        print(f"[pipeline] Processing existing events in {events_path}…")
        processed = self.process_file(events_path)
        print(f"[pipeline] Loaded {processed} historical events. Now tailing…")

        with events_path.open("r", encoding="utf-8", errors="replace") as fh:
            # Seek to end so we only watch new entries
            fh.seek(0, os.SEEK_END)
            while True:
                line = fh.readline()
                if line:
                    rec = parse_line(line)
                    if rec:
                        alerts = self.process_record(rec)
                        for a in alerts:
                            print(
                                f"  🚨 ALERT [{a['type']}] ({a['owasp_category']}) "
                                f"user={a.get('user')} endpoint={a['endpoint']}: "
                                f"{a['explanation'][:60]}…"
                            )
                else:
                    time.sleep(poll_interval)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="API-Sentinel detection pipeline")
    parser.add_argument(
        "--events",
        default=os.getenv("EVENTS_FILE", "data/events.jsonl"),
        help="Path to JSONL event log (default: data/events.jsonl)",
    )
    parser.add_argument(
        "--spec",
        default="openapi/openapi.yaml",
        help="Path to OpenAPI spec (default: openapi/openapi.yaml)",
    )
    parser.add_argument(
        "--tail",
        action="store_true",
        help="Keep running and tail the event log continuously",
    )
    args = parser.parse_args()

    pipeline = Pipeline(spec_path=args.spec)

    if args.tail:
        try:
            pipeline.tail(args.events)
        except KeyboardInterrupt:
            print("\n[pipeline] Stopped.")
    else:
        n = pipeline.process_file(args.events)
        print(f"[pipeline] Processed {n} events.")
        stats = GLOBAL_STATE.to_stats()
        print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
