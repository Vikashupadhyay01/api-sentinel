"""
backend/tests/test_bola.py – unit tests for backend.bola.BOLADetector

Covers:
  - True positive: user accesses an object belonging to another user
  - True positive: user accesses an object ID never seen in their own lists
  - No false positive: user accesses only their own objects (normal traffic)
  - No false positive: unauthenticated request never raises alert
  - Deduplication: same (user, object_id) pair only alerts once
  - Ownership learning: list response correctly maps IDs to owner
  - Alert fields: type="BOLA", severity="HIGH", owasp_category="API1"
  - process_many: batch processing
"""
from __future__ import annotations

import json

import pytest

from backend.bola import BOLADetector, Alert
from backend.parser import Record


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rec(
    method: str = "GET",
    path: str = "/api/v1/orders",
    status: int = 200,
    user: str | None = "alice",
    resp_body: str = "[]",
    req_body: str = "",
) -> Record:
    return Record(
        ts="2026-11-09T05:00:00+00:00",
        method=method,
        path=path,
        query="",
        status=status,
        user=user,
        req_body=req_body,
        resp_body=resp_body,
        latency_ms=1.0,
        blocked=False,
    )


# Alice owns orders 101, 102; Bob owns 201, 202; Carol owns 301
_ALICE_ORDERS = json.dumps([
    {"id": 101, "owner_id": 1, "item": "Laptop"},
    {"id": 102, "owner_id": 1, "item": "Mouse"},
])
_BOB_ORDERS = json.dumps([
    {"id": 201, "owner_id": 2, "item": "Phone"},
    {"id": 202, "owner_id": 2, "item": "Earbuds"},
])
_CAROL_ORDERS = json.dumps([
    {"id": 301, "owner_id": 3, "item": "Monitor"},
])


def _teach_detector(detector: BOLADetector) -> None:
    """Feed list responses so the detector learns ownership."""
    detector.process(_rec(path="/api/v1/orders", user="alice", resp_body=_ALICE_ORDERS))
    detector.process(_rec(path="/api/v1/orders", user="bob",   resp_body=_BOB_ORDERS))
    detector.process(_rec(path="/api/v1/orders", user="carol", resp_body=_CAROL_ORDERS))


# ---------------------------------------------------------------------------
# True-positive tests (BOLA must fire)
# ---------------------------------------------------------------------------

class TestBOLATruePositives:

    def test_alice_reads_bobs_order(self):
        """Alice reads order 201, which belongs to Bob → BOLA alert."""
        d = BOLADetector()
        _teach_detector(d)
        alert = d.process(_rec(path="/api/v1/orders/201", user="alice",
                               resp_body='{"id":201,"owner_id":2}'))
        assert alert is not None
        assert alert.type == "BOLA"
        assert alert.user == "alice"
        assert alert.object_id == "201"

    def test_alice_reads_carols_order(self):
        """Alice reads order 301, which belongs to Carol → BOLA alert."""
        d = BOLADetector()
        _teach_detector(d)
        alert = d.process(_rec(path="/api/v1/orders/301", user="alice",
                               resp_body='{"id":301,"owner_id":3}'))
        assert alert is not None
        assert alert.type == "BOLA"

    def test_bob_reads_alices_order(self):
        """Bob reads order 101, which belongs to Alice → BOLA alert."""
        d = BOLADetector()
        _teach_detector(d)
        alert = d.process(_rec(path="/api/v1/orders/101", user="bob",
                               resp_body='{"id":101,"owner_id":1}'))
        assert alert is not None
        assert alert.type == "BOLA"
        assert alert.user == "bob"

    def test_bola_on_unseen_object_id(self):
        """Alice accesses object 999 that has never appeared in any list → BOLA."""
        d = BOLADetector()
        _teach_detector(d)
        alert = d.process(_rec(path="/api/v1/orders/999", user="alice",
                               resp_body='{"id":999,"owner_id":9}'))
        assert alert is not None
        assert alert.type == "BOLA"
        assert alert.object_id == "999"

    def test_severity_is_high(self):
        d = BOLADetector()
        _teach_detector(d)
        alert = d.process(_rec(path="/api/v1/orders/201", user="alice",
                               resp_body='{"id":201}'))
        assert alert is not None
        assert alert.severity == "HIGH"

    def test_owasp_category_is_api1(self):
        d = BOLADetector()
        _teach_detector(d)
        alert = d.process(_rec(path="/api/v1/orders/201", user="alice",
                               resp_body='{"id":201}'))
        assert alert is not None
        assert alert.owasp_category == "API1"

    def test_alert_has_required_fields(self):
        d = BOLADetector()
        _teach_detector(d)
        alert = d.process(_rec(path="/api/v1/orders/201", user="alice",
                               resp_body='{"id":201}'))
        assert alert is not None
        assert alert.id  # non-empty UUID string
        assert alert.ts  # non-empty timestamp
        assert alert.endpoint  # normalised path
        assert alert.explanation  # human-readable

    def test_alert_endpoint_is_normalised(self):
        d = BOLADetector()
        _teach_detector(d)
        alert = d.process(_rec(path="/api/v1/orders/201", user="alice",
                               resp_body='{"id":201}'))
        assert alert is not None
        assert alert.endpoint == "/api/v1/orders/{id}"

    def test_alert_raw_path_preserved(self):
        d = BOLADetector()
        _teach_detector(d)
        alert = d.process(_rec(path="/api/v1/orders/201", user="alice",
                               resp_body='{"id":201}'))
        assert alert is not None
        assert alert.raw_path == "/api/v1/orders/201"


# ---------------------------------------------------------------------------
# False-positive tests (BOLA must NOT fire for normal traffic)
# ---------------------------------------------------------------------------

class TestBOLAFalsePositives:

    def test_alice_reads_own_order_no_alert(self):
        """Alice reads her own order 101 → no alert."""
        d = BOLADetector()
        _teach_detector(d)
        alert = d.process(_rec(path="/api/v1/orders/101", user="alice",
                               resp_body='{"id":101,"owner_id":1}'))
        assert alert is None, f"False positive! Got: {alert}"

    def test_alice_reads_own_order_102_no_alert(self):
        d = BOLADetector()
        _teach_detector(d)
        alert = d.process(_rec(path="/api/v1/orders/102", user="alice",
                               resp_body='{"id":102,"owner_id":1}'))
        assert alert is None

    def test_bob_reads_own_order_no_alert(self):
        d = BOLADetector()
        _teach_detector(d)
        alert = d.process(_rec(path="/api/v1/orders/201", user="bob",
                               resp_body='{"id":201,"owner_id":2}'))
        assert alert is None

    def test_carol_reads_own_order_no_alert(self):
        d = BOLADetector()
        _teach_detector(d)
        alert = d.process(_rec(path="/api/v1/orders/301", user="carol",
                               resp_body='{"id":301,"owner_id":3}'))
        assert alert is None

    def test_unauthenticated_request_no_alert(self):
        """Requests without a user identity must never raise BOLA alerts."""
        d = BOLADetector()
        alert = d.process(_rec(path="/api/v1/orders/201", user=None,
                               resp_body='{"id":201}'))
        assert alert is None

    def test_list_endpoint_itself_no_alert(self):
        """Calling the list endpoint should learn ownership, not raise alerts."""
        d = BOLADetector()
        alert = d.process(_rec(path="/api/v1/orders", user="alice",
                               resp_body=_ALICE_ORDERS))
        assert alert is None

    def test_non_200_response_no_alert(self):
        """A 404 response on a detail endpoint must not trigger BOLA."""
        d = BOLADetector()
        _teach_detector(d)
        alert = d.process(_rec(path="/api/v1/orders/201", user="alice",
                               status=404, resp_body='{"detail":"Not found"}'))
        assert alert is None

    def test_post_request_no_alert(self):
        """POST requests don't match detail-GET heuristic."""
        d = BOLADetector()
        _teach_detector(d)
        alert = d.process(_rec(method="POST", path="/api/v1/orders",
                               user="alice", resp_body='{"id":201}'))
        assert alert is None


# ---------------------------------------------------------------------------
# Deduplication tests
# ---------------------------------------------------------------------------

class TestBOLADeduplication:

    def test_same_pair_only_alerted_once(self):
        """The same (user, object_id) pair must only produce one alert."""
        d = BOLADetector()
        _teach_detector(d)
        alerts = []
        for _ in range(5):
            a = d.process(_rec(path="/api/v1/orders/201", user="alice",
                               resp_body='{"id":201}'))
            if a:
                alerts.append(a)
        assert len(alerts) == 1

    def test_different_objects_each_alert(self):
        """Different cross-ownership accesses each produce their own alert."""
        d = BOLADetector()
        _teach_detector(d)
        a1 = d.process(_rec(path="/api/v1/orders/201", user="alice", resp_body='{"id":201}'))
        a2 = d.process(_rec(path="/api/v1/orders/301", user="alice", resp_body='{"id":301}'))
        assert a1 is not None
        assert a2 is not None
        assert a1.id != a2.id

    def test_process_many_returns_list(self):
        d = BOLADetector()
        records = [
            _rec(path="/api/v1/orders", user="alice", resp_body=_ALICE_ORDERS),
            _rec(path="/api/v1/orders", user="bob",   resp_body=_BOB_ORDERS),
            _rec(path="/api/v1/orders/101", user="alice", resp_body='{"id":101}'),  # own → no alert
            _rec(path="/api/v1/orders/201", user="alice", resp_body='{"id":201}'),  # BOLA
            _rec(path="/api/v1/orders/301", user="alice", resp_body='{"id":301}'),  # BOLA
        ]
        alerts = d.process_many(records)
        assert len(alerts) == 2
        assert all(a.type == "BOLA" for a in alerts)

