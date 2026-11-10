"""
backend/remediation.py – Security remediations and OWASP descriptions for API-Sentinel.
"""
from __future__ import annotations

OWASP_INFO: dict[str, dict[str, str]] = {
    "API1": {
        "title": "Broken Object Level Authorization (BOLA)",
        "description": "Object-level access controls are missing or improperly validated; attackers manipulate object IDs to access records belonging to other tenants or users.",
        "remediation": "Enforce object-level ownership checks on every request. Validate that the requesting user's identity matches the resource owner (e.g. order.owner_id == current_user.id) at the data layer before querying or updating.",
    },
    "API4": {
        "title": "Unrestricted Resource Consumption",
        "description": "Lack of rate limiting or execution bounds allows excessive traffic that exhausts server CPU, memory, or network bandwidth.",
        "remediation": "Apply sliding-window or token-bucket rate limits per user identity and per IP address. Return HTTP 429 Too Many Requests with a Retry-After header when limits are exceeded.",
    },
    "API6": {
        "title": "Unrestricted Access to Sensitive Business Flows",
        "description": "Automated bots exploit business logic by systematically enumerating sequential IDs, credential stuffing, or bulk scraping.",
        "remediation": "Replace predictable sequential integer IDs with UUIDv4 or encrypted surrogate keys. Implement burst detection, CAPTCHA challenges, or behavioral bot mitigations.",
    },
    "API9": {
        "title": "Improper Inventory Management",
        "description": "Blind spots in API inventory, including undocumented Shadow APIs and outdated, unpatched Zombie API versions still exposed to traffic.",
        "remediation": "Document all live endpoints in openapi/openapi.yaml or remove unlisted routes. For zombie APIs (e.g. /api/v0/), decommission obsolete service handlers and sunset legacy client support.",
    },
}


def get_owasp_description(category: str) -> str:
    """Return the one-line OWASP description for a category code (e.g. 'API1')."""
    info = OWASP_INFO.get(category.upper())
    return info["description"] if info else "OWASP API Security Vulnerability"


def get_remediation(category: str) -> str:
    """Return actionable remediation advice for a category code."""
    info = OWASP_INFO.get(category.upper())
    return info["remediation"] if info else "Implement strict access controls and validate all client input."

