"""
backend/tests/test_api.py – tests for the Detection API (backend.api).

Covers:
  - GET /api/health returns 200 and status ok
  - GET /api/endpoints returns inventory list
  - GET /api/alerts returns alerts list
  - GET /api/stats returns all required summary counters + owasp_breakdown
  - POST /api/analyze: allows normal request
  - POST /api/analyze: blocks BOLA violation (cross-user access)
  - POST /api/analyze: handles unauthenticated request safely
  - CORS headers: Access-Control-Allow-Origin present on responses
"""
from __future__ import annotations

import json
import pytest

from backend.api import app, _pipeline
from backend.parser import Record


@pytest.fixture()
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestHealthEndpoint:

    def test_health_returns_200(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert "service" in data


class TestEndpointsEndpoint:

    def test_get_endpoints_returns_list(self, client):
        resp = client.get("/api/endpoints")
        assert resp.status_code == 200
        assert isinstance(resp.get_json(), list)


class TestAlertsEndpoint:

    def test_get_alerts_returns_list(self, client):
        resp = client.get("/api/alerts")
        assert resp.status_code == 200
        assert isinstance(resp.get_json(), list)


class TestStatsEndpoint:

    def test_get_stats_has_all_keys(self, client):
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.get_json()
        required_keys = {
            "total_requests",
            "total_endpoints",
            "documented_endpoints",
            "shadow_endpoints",
            "zombie_endpoints",
            "total_alerts",
            "blocked_requests",
            "owasp_breakdown",
        }
        assert required_keys.issubset(data.keys())


class TestAnalyzeEndpoint:

    def test_allows_normal_request(self, client):
        payload = {
            "method": "GET",
            "path": "/api/v1/orders",
            "user": "alice",
        }
        resp = client.post("/api/analyze", json=payload)
        assert resp.status_code == 200
        assert resp.get_json()["block"] is False

    def test_blocks_bola_when_ownership_known(self, client):
        # Teach the detector that Bob owns 201
        _pipeline.bola_detector._ownership["201"] = "bob"
        _pipeline.bola_detector._user_ids["bob"] = {"201"}

        payload = {
            "method": "GET",
            "path": "/api/v1/orders/201",
            "user": "alice",  # Alice trying to access Bob's order
        }
        resp = client.post("/api/analyze", json=payload)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["block"] is True
        assert data["owasp_category"] == "API1"
        assert "BOLA" in data["reason"]

    def test_allows_own_object_access(self, client):
        # Alice owns 101
        _pipeline.bola_detector._ownership["101"] = "alice"
        _pipeline.bola_detector._user_ids["alice"] = {"101"}

        payload = {
            "method": "GET",
            "path": "/api/v1/orders/101",
            "user": "alice",
        }
        resp = client.post("/api/analyze", json=payload)
        assert resp.status_code == 200
        assert resp.get_json()["block"] is False

    def test_unauthenticated_request_allowed_by_default(self, client):
        payload = {
            "method": "GET",
            "path": "/api/v0/users",
            "user": None,
        }
        resp = client.post("/api/analyze", json=payload)
        assert resp.status_code == 200
        assert resp.get_json()["block"] is False


class TestCORSHeaders:

    def test_cors_header_on_response(self, client):
        resp = client.get("/api/health")
        assert resp.headers.get("Access-Control-Allow-Origin") == "http://localhost:5173"

    def test_cors_allows_localhost_origin(self, client):
        resp = client.get("/api/health", headers={"Origin": "http://localhost:5173"})
        assert resp.headers.get("Access-Control-Allow-Origin") == "http://localhost:5173"


# ---------------------------------------------------------------------------
# Blocked requests endpoint tests (BUG 1)
# ---------------------------------------------------------------------------

class TestBlockedEndpoint:

    def test_get_blocked_returns_list(self, client):
        resp = client.get("/api/blocked")
        assert resp.status_code == 200
        assert isinstance(resp.get_json(), list)

    def test_blocked_count_equals_list_length_source_of_truth(self, client):
        """Acceptance test: stats['blocked_requests'] MUST always equal len(GET /api/blocked)."""
        stats_resp = client.get("/api/stats")
        blocked_resp = client.get("/api/blocked")
        assert stats_resp.status_code == 200
        assert blocked_resp.status_code == 200

        stats_count = stats_resp.get_json()["blocked_requests"]
        blocked_list = blocked_resp.get_json()
        assert stats_count == len(blocked_list), f"Count {stats_count} != list length {len(blocked_list)}"

    def test_processing_blocked_record_updates_both(self, client):
        """Simulate an enforcement-blocked record; both count and list must increase identically."""
        initial_count = client.get("/api/stats").get_json()["blocked_requests"]

        blocked_rec = Record(
            ts="2026-11-09T08:00:00+00:00",
            method="GET",
            path="/api/v1/orders/201",
            query="",
            status=403,
            user="alice",
            req_body="",
            resp_body='{"error": "Blocked", "reason": "BOLA violation on object 201", "owasp_category": "API1"}',
            latency_ms=0.0,
            blocked=True,
        )
        _pipeline.process_record(blocked_rec)

        stats = client.get("/api/stats").get_json()
        blocked = client.get("/api/blocked").get_json()

        assert stats["blocked_requests"] == initial_count + 1
        assert len(blocked) == stats["blocked_requests"]

        # Verify fields of the newest blocked record
        latest = blocked[0]
        assert latest["user"] == "alice"
        assert latest["method"] == "GET"
        assert latest["path"] == "/api/v1/orders/201"
        assert latest["object_id"] == "201"
        assert "BOLA violation" in latest["reason"]
        assert latest["owasp_category"] == "API1"
        assert latest["status"] == 403

    def test_historical_events_from_events_jsonl_populates_blocked(self, client, tmp_path):
        """Historical events from previous ENFORCE=1 run must populate the list and match count."""
        events_file = tmp_path / "test_events.jsonl"
        with events_file.open("w", encoding="utf-8") as f:
            for i in range(5):
                event = {
                    "ts": f"2026-11-09T08:0{i}:00+00:00",
                    "method": "GET",
                    "path": f"/api/v1/orders/{200 + i}",
                    "query": "",
                    "user": "alice",
                    "status": 403,
                    "req_body": "",
                    "resp_body": '{"error": "Blocked", "reason": "BOLA violation"}',
                    "latency_ms": 0.0,
                    "blocked": True,
                }
                f.write(json.dumps(event) + "\n")

        # Create isolated pipeline and state
        from backend.pipeline import Pipeline, PipelineState
        test_state = PipelineState()
        test_pipeline = Pipeline(spec_path="openapi/openapi.yaml", state=test_state)

        count = test_pipeline.process_file(events_file)
        assert count == 5
        assert len(test_state.blocked_requests) == 5
        stats = test_state.to_stats()
        assert stats["blocked_requests"] == 5
        assert stats["blocked_requests"] == len(test_state.blocked_requests)


