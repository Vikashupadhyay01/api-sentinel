"""
backend/pii.py – PII masking for event payloads.

Masks personally-identifiable information in any string before it is stored
in the event log or sent to the dashboard.  Masking is non-reversible (the
original value is replaced with a fixed placeholder) so no sensitive data
leaks into logs or the UI.

Patterns masked
---------------
  - Credit / debit card numbers  → ``[CARD-MASKED]``
  - Bearer tokens                → ``[TOKEN-MASKED]``
  - E-mail addresses             → ``[EMAIL-MASKED]``
  - Phone numbers (E.164 + common formats) → ``[PHONE-MASKED]``
  - card_last4 field values (4-digit strings in JSON) remain as-is
    because they are not sensitive on their own (last 4 digits only).

Usage
-----
  from backend.pii import mask

  clean = mask('{"email":"alice@example.com","token":"token-alice"}')
  # → '{"email":"[EMAIL-MASKED]","token":"[TOKEN-MASKED]"}'
"""
from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Compiled regex patterns
# Order matters: more specific patterns must come before broader ones.
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Bearer tokens (project-specific format: "token-<username>")
    (
        re.compile(r'\btoken-[a-zA-Z0-9_\-]+\b'),
        "[TOKEN-MASKED]",
    ),
    # 16-digit card numbers with optional separators (spaces or hyphens)
    # e.g. 4111 1111 1111 1111 or 4111-1111-1111-1111 or 4111111111111111
    (
        re.compile(
            r'\b(?:\d[ \-]?){15}\d\b'
        ),
        "[CARD-MASKED]",
    ),
    # E-mail addresses
    (
        re.compile(
            r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
        ),
        "[EMAIL-MASKED]",
    ),
    # Phone numbers: E.164 (+1234567890…), common US (555-123-4567),
    # international (+44 20 7946 0958), and 10-digit strings
    (
        re.compile(
            r'(?<!\d)'                       # not preceded by digit
            r'(?:\+\d{1,3}[\s\-]?)?'        # optional country code
            r'(?:\(?\d{3}\)?[\s\-]?)'       # area code
            r'\d{3}[\s\-]?\d{4}'            # local number
            r'(?!\d)'                        # not followed by digit
        ),
        "[PHONE-MASKED]",
    ),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def mask(text: str) -> str:
    """Apply all PII masking patterns to *text* and return the redacted string.

    Parameters
    ----------
    text:
        Any string — typically a serialised JSON body or a URL.

    Returns
    -------
    str
        The input string with all detected PII replaced by placeholders.
    """
    for pattern, placeholder in _PATTERNS:
        text = pattern.sub(placeholder, text)
    return text


def mask_record_bodies(record_dict: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow copy of a record dict with ``req_body`` and
    ``resp_body`` run through :func:`mask`.

    Useful when serialising event dicts for the dashboard or the alert API.
    """
    out = dict(record_dict)
    if "req_body" in out and isinstance(out["req_body"], str):
        out["req_body"] = mask(out["req_body"])
    if "resp_body" in out and isinstance(out["resp_body"], str):
        out["resp_body"] = mask(out["resp_body"])
    return out


def mask_alert(alert_dict: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of an alert dict with ``explanation``, ``req_body``, and ``resp_body`` masked."""
    out = dict(alert_dict)
    if "explanation" in out and isinstance(out["explanation"], str):
        out["explanation"] = mask(out["explanation"])
    if "req_body" in out and isinstance(out["req_body"], str):
        out["req_body"] = mask(out["req_body"])
    if "resp_body" in out and isinstance(out["resp_body"], str):
        out["resp_body"] = mask(out["resp_body"])
    if "remediation" in out and isinstance(out["remediation"], str):
        out["remediation"] = mask(out["remediation"])
    return out

