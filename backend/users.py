"""
backend/users.py – User threat profile aggregation for API-Sentinel.

Computes threat ranking for observed users:
  - Total alerts triggered
  - Blocked enforcement actions
  - Primary threat category (OWASP API1, API4, API6, etc.)
  - Severity breakdown
"""
from __future__ import annotations

from typing import Any, Mapping, Sequence


def compute_top_users(
    alerts: Sequence[Mapping[str, Any]] | None = None,
    blocked_requests: Sequence[Mapping[str, Any]] | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Aggregate threat metrics per user and return sorted by alert/threat count."""
    alerts = alerts or []
    blocked_requests = blocked_requests or []

    user_profiles: dict[str, dict[str, Any]] = {}

    def _get_profile(username: str) -> dict[str, Any]:
        u = username or "anonymous"
        if u not in user_profiles:
            user_profiles[u] = {
                "user": u,
                "alert_count": 0,
                "blocked_count": 0,
                "owasp_counts": {},
                "severities": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "top_threat": "None",
            }
        return user_profiles[u]

    # Process alerts
    for a in alerts:
        u = a.get("user") or "anonymous"
        prof = _get_profile(u)
        prof["alert_count"] += 1

        sev = str(a.get("severity", "MEDIUM")).upper()
        if sev not in prof["severities"]:
            prof["severities"][sev] = 0
        prof["severities"][sev] += 1

        owasp = a.get("owasp_category", "UNKNOWN")
        prof["owasp_counts"][owasp] = prof["owasp_counts"].get(owasp, 0) + 1

    # Process blocked requests
    for b in blocked_requests:
        u = b.get("user") or "anonymous"
        prof = _get_profile(u)
        prof["blocked_count"] += 1
        owasp = b.get("owasp_category", "API1")
        prof["owasp_counts"][owasp] = prof["owasp_counts"].get(owasp, 0) + 1

    # Determine top threat for each user
    friendly_owasp = {
        "API1": "API1: BOLA",
        "API4": "API4: Rate Limit",
        "API6": "API6: Enumeration",
        "API9": "API9: Shadow/Zombie",
    }

    results: list[dict[str, Any]] = []
    for u, prof in user_profiles.items():
        if prof["owasp_counts"]:
            # Find most common category
            top_cat = max(prof["owasp_counts"].items(), key=lambda kv: kv[1])[0]
            prof["top_threat"] = friendly_owasp.get(top_cat, top_cat)
        results.append(prof)

    # Sort by alert_count desc, then blocked_count desc
    results.sort(key=lambda p: (p["alert_count"], p["blocked_count"]), reverse=True)

    return results[:limit]

