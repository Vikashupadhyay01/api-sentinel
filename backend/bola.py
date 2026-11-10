"""
backend/bola.py – BOLA (Broken Object Level Authorization) detection engine.

OWASP API1:2023 – Broken Object Level Authorization.

Algorithm
---------
Phase A – ownership learning:
  When a user calls a *list* endpoint (e.g. GET /api/v1/orders) and receives
  a 200 response, parse the JSON array and record every object ID found as
  "owned by this user".

Phase B – access auditing:
  When a user calls a *detail* endpoint (e.g. GET /api/v1/orders/101) and
  - the accessed ID belongs to a *different* user (learned in Phase A), OR
  - the accessed ID has *never* appeared in this user's own list responses,
  emit a BOLA Alert with severity "HIGH".

Limitations (acceptable for a lab):
  - Ownership is inferred heuristically from list responses; it is not
    authoritative.
  - Only integer path IDs are tracked (UUID support is trivially addable).
  - The detector is stateful in-process; it resets on restart.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Optional

from backend.parser import Record
from backend.discovery import normalize_path
from backend.remediation import get_owasp_description, get_remediation


# ---------------------------------------------------------------------------
# Alert model
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    """A single security finding emitted by any detector.

    Attributes
    ----------
    id:
        Unique alert identifier (UUID4 string).
    ts:
        ISO-8601 UTC timestamp when the alert was raised.
    type:
        Short machine-readable alert type (e.g. ``"BOLA"``).
    severity:
        ``"HIGH"`` | ``"MEDIUM"`` | ``"LOW"`` | ``"INFO"``.
    user:
        Username of the actor who triggered the alert, or ``None``.
    endpoint:
        Normalised path of the accessed endpoint (e.g.
        ``"/api/v1/orders/{id}"``).
    object_id:
        The specific object ID accessed (e.g. ``"201"``).
    owasp_category:
        OWASP API Security Top-10 category (e.g. ``"API1"``).
    explanation:
        Human-readable description of why this was flagged.
    raw_path:
        Original un-normalised path from the request.
    method:
        HTTP method (GET, POST, etc.)
    status:
        HTTP response status code.
    req_body:
        Raw request body (PII-masked upon storage).
    resp_body:
        Raw response body (PII-masked upon storage).
    remediation:
        Recommended fix / mitigation advice.
    owasp_description:
        Official OWASP Top 10 category description.
    """

    id: str
    ts: str
    type: str
    severity: str
    user: Optional[str]
    endpoint: str
    object_id: str
    owasp_category: str
    explanation: str
    raw_path: str = ""
    method: str = ""
    status: Optional[int] = None
    req_body: str = ""
    resp_body: str = ""
    remediation: str = ""
    owasp_description: str = ""

    def to_dict(self) -> dict:
        """Serialise to a JSON-safe dict."""
        return {
            "id": self.id,
            "ts": self.ts,
            "type": self.type,
            "severity": self.severity,
            "user": self.user,
            "endpoint": self.endpoint,
            "object_id": self.object_id,
            "owasp_category": self.owasp_category,
            "explanation": self.explanation,
            "raw_path": self.raw_path,
            "method": self.method,
            "status": self.status,
            "req_body": self.req_body,
            "resp_body": self.resp_body,
            "remediation": self.remediation or get_remediation(self.owasp_category),
            "owasp_description": self.owasp_description or get_owasp_description(self.owasp_category),
        }


def _make_alert(
    alert_type: str,
    severity: str,
    user: Optional[str],
    endpoint: str,
    object_id: str,
    owasp_category: str,
    explanation: str,
    raw_path: str = "",
    method: str = "",
    status: Optional[int] = None,
    req_body: str = "",
    resp_body: str = "",
    remediation: str = "",
    owasp_description: str = "",
) -> Alert:
    """Create an :class:`Alert` with a fresh UUID and UTC timestamp."""
    return Alert(
        id=str(uuid.uuid4()),
        ts=datetime.now(timezone.utc).isoformat(),
        type=alert_type,
        severity=severity,
        user=user,
        endpoint=endpoint,
        object_id=object_id,
        owasp_category=owasp_category,
        explanation=explanation,
        raw_path=raw_path,
        method=method,
        status=status,
        req_body=req_body,
        resp_body=resp_body,
        remediation=remediation or get_remediation(owasp_category),
        owasp_description=owasp_description or get_owasp_description(owasp_category),
    )


# ---------------------------------------------------------------------------
# Helpers – extract object IDs from list responses
# ---------------------------------------------------------------------------

def _extract_ids_from_list_response(resp_body: str, id_field: str = "id") -> set[str]:
    """Parse a JSON-array response body and collect values of *id_field*.

    Returns an empty set when the body is not a JSON array or lacks the field.

    Parameters
    ----------
    resp_body:
        Raw response body string.
    id_field:
        Name of the primary-key field to look for (default ``"id"``).
    """
    try:
        data = json.loads(resp_body)
    except (json.JSONDecodeError, TypeError):
        return set()

    if not isinstance(data, list):
        return set()

    ids: set[str] = set()
    for item in data:
        if isinstance(item, dict) and id_field in item:
            ids.add(str(item[id_field]))
    return ids


def _extract_path_id(path: str) -> Optional[str]:
    """Extract the last numeric segment from *path*, if present.

    ``/api/v1/orders/201`` → ``"201"``
    ``/api/v1/orders``     → ``None``
    """
    segments = path.rstrip("/").split("/")
    for seg in reversed(segments):
        if seg.isdigit():
            return seg
    return None


# ---------------------------------------------------------------------------
# BOLA Detector (stateful, single-process)
# ---------------------------------------------------------------------------

class BOLADetector:
    """Stateful BOLA detector that learns ownership from list responses.

    Usage
    -----
    ::

        detector = BOLADetector()
        alerts = []
        for record in iter_records("data/events.jsonl"):
            alert = detector.process(record)
            if alert:
                alerts.append(alert)
    """

    def __init__(self) -> None:
        # ownership_map[object_id] = username who owns it
        self._ownership: dict[str, str] = {}

        # per-user set of IDs they have legitimately accessed via list endpoints
        self._user_ids: dict[str, set[str]] = {}

        # track already-raised (user, object_id) pairs to avoid duplicate alerts
        self._alerted: set[tuple[str, str]] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process(self, record: Record) -> Optional[Alert]:
        """Process one :class:`~backend.parser.Record` and return an alert if warranted.

        Returns ``None`` for normal (non-violating) requests.
        """
        if record.user is None:
            return None  # unauthenticated requests cannot be BOLA

        norm_path = normalize_path(record.path)

        # Phase A: learn ownership from list endpoint responses
        if self._is_list_endpoint(record):
            self._learn_ownership(record)
            return None

        # Phase B: audit detail endpoint accesses
        if self._is_detail_endpoint(record):
            return self._audit_detail(record, norm_path)

        return None

    def process_many(self, records: Iterable[Record]) -> list[Alert]:
        """Process an iterable of records; return all BOLA alerts found."""
        alerts: list[Alert] = []
        for rec in records:
            alert = self.process(rec)
            if alert:
                alerts.append(alert)
        return alerts

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _is_list_endpoint(self, record: Record) -> bool:
        """True when the record looks like a *successful* list response.

        Heuristic: GET request, status 200, normalised path ends in a
        collection name (no ``{id}`` suffix), and the response body is
        a JSON array.
        """
        if record.method != "GET" or record.status != 200:
            return False
        norm = normalize_path(record.path)
        # A list endpoint's normalised path does NOT end in "{id}"
        if norm.endswith("/{id}") or norm.endswith("{id}"):
            return False
        # Confirm the body is actually a JSON array
        try:
            parsed = json.loads(record.resp_body)
            return isinstance(parsed, list)
        except (json.JSONDecodeError, TypeError):
            return False

    def _is_detail_endpoint(self, record: Record) -> bool:
        """True when the record looks like a *successful* single-object GET.

        Heuristic: GET request, status 200, path contains a numeric ID.
        """
        if record.method != "GET" or record.status != 200:
            return False
        return _extract_path_id(record.path) is not None

    def _learn_ownership(self, record: Record) -> None:
        """Record object IDs from a list response as owned by this user."""
        ids = _extract_ids_from_list_response(record.resp_body)
        user = record.user
        assert user is not None  # already checked in process()

        if user not in self._user_ids:
            self._user_ids[user] = set()
        self._user_ids[user].update(ids)

        for obj_id in ids:
            # Only set ownership the first time we see an ID; first user to
            # list it is the presumed owner.
            if obj_id not in self._ownership:
                self._ownership[obj_id] = user

    def _audit_detail(self, record: Record, norm_path: str) -> Optional[Alert]:
        """Check a detail-endpoint access for BOLA.

        Returns an :class:`Alert` when:
        - The object ID is known to belong to *another* user, OR
        - The object ID has never appeared in this user's own list history.
        """
        user = record.user
        assert user is not None

        obj_id = _extract_path_id(record.path)
        if obj_id is None:
            return None

        # De-duplicate: don't re-alert for the same (user, object) pair
        pair = (user, obj_id)
        if pair in self._alerted:
            return None

        known_owner = self._ownership.get(obj_id)
        user_own_ids = self._user_ids.get(user, set())

        if known_owner is not None and known_owner != user:
            # Definitive BOLA: ID belongs to a different user
            self._alerted.add(pair)
            return _make_alert(
                alert_type="BOLA",
                severity="HIGH",
                user=user,
                endpoint=norm_path,
                object_id=obj_id,
                owasp_category="API1",
                explanation=(
                    f"User '{user}' accessed object {obj_id} "
                    f"which belongs to '{known_owner}'. "
                    f"OWASP API1:2023 – Broken Object Level Authorization."
                ),
                raw_path=record.path,
                method=record.method,
                status=record.status,
                req_body=record.req_body,
                resp_body=record.resp_body,
            )

        if known_owner is None and obj_id not in user_own_ids:
            # Object ID not seen in any list response – potential enumeration / BOLA
            self._alerted.add(pair)
            return _make_alert(
                alert_type="BOLA",
                severity="HIGH",
                user=user,
                endpoint=norm_path,
                object_id=obj_id,
                owasp_category="API1",
                explanation=(
                    f"User '{user}' accessed object {obj_id} "
                    f"which was never seen in their own list responses. "
                    f"Possible BOLA / unauthorized access. "
                    f"OWASP API1:2023 – Broken Object Level Authorization."
                ),
                raw_path=record.path,
                method=record.method,
                status=record.status,
                req_body=record.req_body,
                resp_body=record.resp_body,
            )

        return None  # access is consistent with ownership

