"""
backend/tests/test_phase4.py – Tests for Phase 4:
  - Runtime Mode Toggle (GET/POST /api/mode)
  - Interactive Demo Attack Simulation (POST /api/demo/attack with localhost validation)
  - Demo Reset (POST /api/demo/reset)
"""
import pytest
from backend.api import app, GLOBAL_STATE, _pipeline
from backend.demo_helper import run_demo_attack, _validate_target_url


# ---------------------------------------------------------------------------
# 1. Mode Toggle Tests
# ---------------------------------------------------------------------------

class TestModeToggle:
    @pytest.fixture
    def client(self):
        app.config["TESTING"] = True
        with app.test_client() as c:
            yield c

    def test_get_mode(self, client):
        resp = client.get("/api/mode")
        assert resp.status_code == 200
        assert resp.get_json()["mode"] in ("passive", "enforce")

    def test_post_mode_toggles_mode(self, client):
        resp = client.post("/api/mode", json={"mode": "enforce"})
        assert resp.status_code == 200
        assert resp.get_json()["mode"] == "enforce"
        assert GLOBAL_STATE.mode == "enforce"

        resp2 = client.post("/api/mode", json={"mode": "passive"})
        assert resp2.status_code == 200
        assert resp2.get_json()["mode"] == "passive"
        assert GLOBAL_STATE.mode == "passive"

    def test_post_mode_invalid_rejects_400(self, client):
        resp = client.post("/api/mode", json={"mode": "super_enforce"})
        assert resp.status_code == 400
        assert "Invalid mode" in resp.get_json()["error"]


# ---------------------------------------------------------------------------
# 2. Demo Helper Safety Tests
# ---------------------------------------------------------------------------

class TestDemoHelperSafety:
    def test_validate_target_allows_localhost_8080(self):
        assert _validate_target_url("http://127.0.0.1:8080") == "http://127.0.0.1:8080"
        assert _validate_target_url("http://localhost:8080") == "http://localhost:8080"

    def test_validate_target_rejects_external_hosts(self):
        with pytest.raises(ValueError, match="Security Violation"):
            _validate_target_url("http://example.com:8080")

        with pytest.raises(ValueError, match="Security Violation"):
            _validate_target_url("http://192.168.1.1:8080")

        with pytest.raises(ValueError, match="Security Violation"):
            _validate_target_url("http://10.0.0.1:8080")

    def test_validate_target_rejects_invalid_ports(self):
        with pytest.raises(ValueError, match="Security Violation"):
            _validate_target_url("http://127.0.0.1:22")

        with pytest.raises(ValueError, match="Security Violation"):
            _validate_target_url("http://127.0.0.1:443")


# ---------------------------------------------------------------------------
# 3. Demo API Endpoints Tests
# ---------------------------------------------------------------------------

class TestDemoEndpoints:
    @pytest.fixture
    def client(self):
        app.config["TESTING"] = True
        with app.test_client() as c:
            yield c

    def test_demo_attack_rejects_non_localhost(self, client):
        resp = client.post("/api/demo/attack", json={"target": "http://evil.com:8080"})
        assert resp.status_code == 400
        assert "Security Violation" in resp.get_json()["error"]

    def test_demo_reset_clears_state(self, client):
        # Populate dummy state
        GLOBAL_STATE.alerts.append({"id": "dummy"})
        GLOBAL_STATE.blocked_requests.append({"id": "dummy-b"})
        _pipeline.bola_detector._ownership["999"] = "alice"

        resp = client.post("/api/demo/reset")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "ok"

        assert len(GLOBAL_STATE.alerts) == 0
        assert len(GLOBAL_STATE.blocked_requests) == 0
        assert len(_pipeline.bola_detector._ownership) == 0

