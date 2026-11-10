"""
backend/risk.py – Risk score calculation engine for API-Sentinel.

Calculates a 0–100 risk score and qualitative threat level (LOW, MEDIUM, HIGH, CRITICAL)
based on detected security findings:
  - Active alert counts weighted by severity (CRITICAL: 25, HIGH: 20, MEDIUM: 10, LOW: 2)
  - Endpoint exposure risks (Shadow and Zombie API counts)
  - Rate of attack / blocked enforcement actions

Scale:
  0 – 25   : LOW (Minimal or normal traffic)
  26 – 50  : MEDIUM (Unmanaged endpoints or rate limit spikes)
  51 – 75  : HIGH (BOLA violations or automated scraping detected)
  76 – 100 : CRITICAL (Multiple high-severity flaws or active attacks)
"""
from __future__ import annotations

from typing import Any, Mapping, Sequence


SEVERITY_WEIGHTS: dict[str, int] = {
    "CRITICAL": 25,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 2,
}

OWASP_WEIGHTS: dict[str, int] = {
    "API1": 25,  # BOLA is the #1 critical API flaw
    "API6": 20,  # Enumeration / Business flow abuse
    "API4": 10,  # Rate limit exceedance
    "API9": 15,  # Shadow / Zombie APIs
}


def compute_risk_score(
    alerts: Sequence[Mapping[str, Any]] | None = None,
    shadow_count: int = 0,
    zombie_count: int = 0,
    blocked_count: int = 0,
) -> dict[str, Any]:
    """Calculate the 0–100 risk score and level from current pipeline metrics.

    Returns:
        dict with keys:
          - score: int (0 to 100)
          - level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
          - color: hex color code for UI badges / charts
          - breakdown: dict of points by category
    """
    alerts = alerts or []
    
    if not alerts and shadow_count == 0 and zombie_count == 0 and blocked_count == 0:
        return {
            "score": 0,
            "level": "LOW",
            "color": "#10b981",
            "breakdown": {
                "alerts_points": 0,
                "shadow_points": 0,
                "zombie_points": 0,
                "blocked_points": 0,
            },
        }

    # Points from alerts
    alert_points = 0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in alerts:
        sev = str(a.get("severity", "MEDIUM")).upper()
        if sev not in severity_counts:
            sev = "MEDIUM"
        severity_counts[sev] += 1
        alert_points += SEVERITY_WEIGHTS.get(sev, 10)

    # Cap raw alert contribution to avoid one single category overflowing without bounds
    # while still allowing high severity alerts to push the score up
    # Zombie APIs present persistent architectural danger (unpatched routes)
    zombie_points = min(30, zombie_count * 15)

    # Shadow APIs present visibility gaps
    shadow_points = min(20, shadow_count * 10)

    # Blocked requests indicate active attacker attempts
    blocked_points = min(15, blocked_count * 5)

    raw_score = alert_points + zombie_points + shadow_points + blocked_points
    score = min(100, max(0, int(raw_score)))

    # Determine risk level
    if score <= 25:
        level = "LOW"
        color = "#10b981"  # Emerald green
    elif score <= 50:
        level = "MEDIUM"
        color = "#f59e0b"  # Amber yellow
    elif score <= 75:
        level = "HIGH"
        color = "#f97316"  # Orange
    else:
        level = "CRITICAL"
        color = "#ef4444"  # Red

    return {
        "score": score,
        "level": level,
        "color": color,
        "breakdown": {
            "alerts_points": alert_points,
            "shadow_points": shadow_points,
            "zombie_points": zombie_points,
            "blocked_points": blocked_points,
            "severity_counts": severity_counts,
        },
    }

