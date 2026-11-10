"""
backend/tests/test_phase2.py – Tests for Phase 2:
  - Risk score calculation engine
  - Timeline 15-minute 10-second bucketing
  - Top users threat aggregation
  - API endpoints /api/timeline and /api/top-users
"""
import time
import pytest
from backend.api import app
from backend.pipeline import GLOBAL_STATE, Pipeline
from backend.risk import compute_risk_score
from backend.timeline import TimelineTracker
from backend.users import compute_top_users


# ---------------------------------------------------------------------------
# 1. Risk Score Engine Tests
# ---------------------------------------------------------------------------

class TestRiskScore:
    def test_zero_state_gives_zero_low_risk(self):
        res = compute_risk_score([], shadow_count=0, zombie_count=0, blocked_count=0)
        assert res["score"] == 0
        assert res["level"] == "LOW"
        assert res["color"] == "#10b981"

    def test_low_severity_alerts(self):
        alerts = [{"severity": "LOW"} for _ in range(3)]
        res = compute_risk_score(alerts, shadow_count=0, zombie_count=0, blocked_count=0)
        assert res["score"] == 6
        assert res["level"] == "LOW"

    def test_medium_risk_level(self):
        # 1 medium alert (+10) + 1 shadow endpoint (+10) + 1 blocked (+5) = 25 -> boundary LOW/MEDIUM
        # Let's add 2 medium alerts (+20) + 1 shadow (+10) = 30 -> MEDIUM
        alerts = [{"severity": "MEDIUM"}, {"severity": "MEDIUM"}]
        res = compute_risk_score(alerts, shadow_count=1, zombie_count=0, blocked_count=0)
        assert res["score"] == 30
        assert res["level"] == "MEDIUM"
        assert res["color"] == "#f59e0b"

    def test_high_risk_level(self):
        # 2 high alerts (40) + 1 zombie (15) = 55 -> HIGH
        alerts = [{"severity": "HIGH"}, {"severity": "HIGH"}]
        res = compute_risk_score(alerts, shadow_count=0, zombie_count=1, blocked_count=0)
        assert res["score"] == 55
        assert res["level"] == "HIGH"
        assert res["color"] == "#f97316"

    def test_critical_risk_level_and_cap_at_100(self):
        # Many critical alerts
        alerts = [{"severity": "CRITICAL"} for _ in range(10)]
        res = compute_risk_score(alerts, shadow_count=5, zombie_count=5, blocked_count=10)
        assert res["score"] == 100
        assert res["level"] == "CRITICAL"
        assert res["color"] == "#ef4444"


# ---------------------------------------------------------------------------
# 2. Timeline Tracker Tests
# ---------------------------------------------------------------------------

class TestTimelineTracker:
    def test_tracker_returns_correct_number_of_buckets(self):
        tracker = TimelineTracker(window_seconds=900, bucket_size=10)
        buckets = tracker.get_buckets()
        assert len(buckets) == 90  # 900 / 10 = 90
        for b in buckets:
            assert "start_epoch" in b
            assert "label" in b
            assert "requests" in b
            assert "alerts" in b
            assert "blocked" in b

    def test_tracker_records_events_into_proper_buckets(self):
        tracker = TimelineTracker(window_seconds=900, bucket_size=10)
        now = 1700000000.0  # Fixed epoch timestamp for deterministic testing
        
        # Record 2 requests, 1 alert, 1 blocked at now
        tracker.record_request(now)
        tracker.record_request(now + 2)
        tracker.record_alert(now + 3)
        tracker.record_blocked(now + 4)

        buckets = tracker.get_buckets(end_epoch=now + 5)
        last_bucket = buckets[-1]
        assert last_bucket["requests"] == 2
        assert last_bucket["alerts"] == 1
        assert last_bucket["blocked"] == 1

    def test_tracker_clear(self):
        tracker = TimelineTracker(window_seconds=900, bucket_size=10)
        tracker.record_request(100)
        tracker.clear()
        assert len(tracker._request_epochs) == 0


# ---------------------------------------------------------------------------
# 3. User Threat Ranking Tests
# ---------------------------------------------------------------------------

class TestUserThreatRanking:
    def test_top_users_aggregates_and_sorts(self):
        alerts = [
            {"user": "alice", "severity": "HIGH", "owasp_category": "API1"},
            {"user": "alice", "severity": "HIGH", "owasp_category": "API1"},
            {"user": "bob", "severity": "MEDIUM", "owasp_category": "API4"},
        ]
        blocked = [
            {"user": "alice", "owasp_category": "API1"},
        ]
        top = compute_top_users(alerts, blocked)
        assert len(top) == 2
        assert top[0]["user"] == "alice"
        assert top[0]["alert_count"] == 2
        assert top[0]["blocked_count"] == 1
        assert "API1" in top[0]["top_threat"]
        assert top[1]["user"] == "bob"
        assert top[1]["alert_count"] == 1


# ---------------------------------------------------------------------------
# 4. API Endpoints Tests
# ---------------------------------------------------------------------------

class TestPhase2Endpoints:
    @pytest.fixture
    def client(self):
        app.config["TESTING"] = True
        with app.test_client() as c:
            yield c

    def test_get_timeline_endpoint(self, client):
        resp = client.get("/api/timeline")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "buckets" in data
        assert len(data["buckets"]) == 90
        assert data["interval_seconds"] == 10
        assert data["window_minutes"] == 15

    def test_get_top_users_endpoint(self, client):
        resp = client.get("/api/top-users")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)

    def test_stats_includes_risk_and_top_users(self, client):
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "risk_score" in data
        assert "risk_level" in data
        assert "risk_color" in data
        assert "risk_breakdown" in data
        assert "top_users" in data

