"""
backend/export.py – Export generators for API-Sentinel:
  - CSV exports (alerts, blocked requests)
  - JSON exports (alerts, blocked requests)
  - Discovered OpenAPI YAML contract with x-sentinel-status tags
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

from backend.discovery import EndpointInfo, load_openapi
from backend.pii import mask


def export_alerts_csv(alerts: Sequence[Mapping[str, Any]]) -> str:
    """Generate a CSV string of all alerts with PII masked."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Alert ID",
        "Timestamp",
        "Type",
        "Severity",
        "OWASP Category",
        "User",
        "Endpoint",
        "Object ID",
        "Method",
        "Status",
        "Explanation",
        "Remediation",
    ])

    for a in alerts:
        writer.writerow([
            a.get("id", ""),
            a.get("ts", ""),
            a.get("type", ""),
            a.get("severity", ""),
            a.get("owasp_category", ""),
            a.get("user", "") or "anonymous",
            a.get("endpoint", ""),
            a.get("object_id", ""),
            a.get("method", ""),
            a.get("status", "") or "",
            mask(str(a.get("explanation", ""))),
            mask(str(a.get("remediation", ""))),
        ])

    return output.getvalue()


def export_alerts_json(alerts: Sequence[Mapping[str, Any]]) -> str:
    """Generate a formatted JSON string of all alerts with PII masked."""
    cleaned = []
    for a in alerts:
        item = dict(a)
        if "explanation" in item:
            item["explanation"] = mask(str(item["explanation"]))
        if "remediation" in item:
            item["remediation"] = mask(str(item["remediation"]))
        if "req_body" in item and item["req_body"]:
            item["req_body"] = mask(str(item["req_body"]))
        if "resp_body" in item and item["resp_body"]:
            item["resp_body"] = mask(str(item["resp_body"]))
        cleaned.append(item)
    return json.dumps(cleaned, indent=2)


def export_blocked_csv(blocked_requests: Sequence[Mapping[str, Any]]) -> str:
    """Generate a CSV string of all blocked requests with PII masked."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Block ID",
        "Timestamp",
        "User",
        "Method",
        "Path",
        "Object ID",
        "HTTP Status",
        "Block Reason",
        "OWASP Category",
    ])

    for b in blocked_requests:
        writer.writerow([
            b.get("id", ""),
            b.get("time", "") or b.get("ts", ""),
            b.get("user", "") or "anonymous",
            b.get("method", "GET"),
            b.get("path", ""),
            b.get("object_id", ""),
            b.get("status", 403),
            mask(str(b.get("reason", "Blocked by API-Sentinel enforcement"))),
            b.get("owasp_category", "API1"),
        ])

    return output.getvalue()


def export_discovered_openapi(
    inventory: Mapping[tuple[str, str], EndpointInfo],
    spec_path: str | Path = "openapi/openapi.yaml",
) -> str:
    """Generate an updated OpenAPI YAML containing documented, shadow, and zombie endpoints.

    Annotates live routes with:
      - x-sentinel-status: "documented" | "shadow" | "zombie"
      - x-sentinel-hits: hit_count
      - x-sentinel-owasp: OWASP category (e.g. API9)
    """
    spec_path = Path(spec_path)
    base_spec: dict[str, Any] = {}

    if spec_path.exists():
        try:
            with spec_path.open("r", encoding="utf-8") as f:
                base_spec = yaml.safe_load(f) or {}
        except Exception:
            base_spec = {}

    if not base_spec:
        base_spec = {
            "openapi": "3.0.3",
            "info": {
                "title": "API-Sentinel Discovered API Inventory",
                "version": "1.1.0",
                "description": "Complete runtime inventory containing documented, shadow, and zombie endpoints.",
            },
            "paths": {},
        }

    paths = base_spec.setdefault("paths", {})

    for (method, norm_path), info in inventory.items():
        m_lower = method.lower()
        path_item = paths.setdefault(norm_path, {})
        op = path_item.setdefault(m_lower, {})

        # Annotate status
        op["x-sentinel-status"] = info.classification
        op["x-sentinel-hits"] = info.hit_count
        if info.owasp_category:
            op["x-sentinel-owasp"] = info.owasp_category

        if info.classification == "shadow":
            op.setdefault("summary", f"Shadow API: {method} {norm_path}")
            op.setdefault(
                "description",
                "Undocumented live route discovered during runtime traffic observation (OWASP API9:2023).",
            )
            op.setdefault("responses", {"200": {"description": "Observed runtime response"}})
        elif info.classification == "zombie":
            op.setdefault("summary", f"Zombie API: {method} {norm_path} (Deprecated)")
            op.setdefault(
                "description",
                "Unmaintained legacy API version still exposed and accepting traffic (OWASP API9:2023).",
            )
            op["deprecated"] = True
            op.setdefault("responses", {"200": {"description": "Observed legacy response"}})
        else:
            op.setdefault("summary", f"{method} {norm_path}")
            op.setdefault("responses", {"200": {"description": "Documented contract endpoint"}})

    return yaml.dump(base_spec, sort_keys=False, allow_unicode=True)

