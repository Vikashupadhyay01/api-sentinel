"""
backend/tests/test_phase3.py – Tests for Phase 3:
  - PDF Security Report generation
  - CSV & JSON alerts export (with PII masking)
  - CSV blocked requests export (with PII masking)
  - Discovered OpenAPI YAML export (with x-sentinel-status tags)
  - API endpoints /api/report.pdf and /api/export/*
"""
import json
import pytest
import yaml

from backend.api import app
from backend.discovery import EndpointInfo
from backend.export import (
    export_alerts_csv,
    export_alerts_json,
    export_blocked_csv,
    export_discovered_openapi,
)
from backend.report import generate_security_report_pdf


# ---------------------------------------------------------------------------
# 1. PDF Report Tests
# ---------------------------------------------------------------------------

class TestPDFReport:
    def test_pdf_generation_empty_state(self):
        pdf = generate_security_report_pdf(
            stats={
                "total_requests": 0,
                "total_endpoints": 0,
                "documented_endpoints": 0,
                "shadow_endpoints": 0,
                "zombie_endpoints": 0,
                "owasp_breakdown": {},
            },
            inventory=[],
            alerts=[],
            blocked_requests=[],
            enforcement_mode=False,
        )
        assert isinstance(pdf, bytes)
        assert pdf.startswith(b"%PDF-")
        assert len(pdf) > 1000

    def test_pdf_generation_populated_state(self):
        pdf = generate_security_report_pdf(
            stats={
                "total_requests": 150,
                "total_endpoints": 6,
                "documented_endpoints": 4,
                "shadow_endpoints": 1,
                "zombie_endpoints": 1,
                "owasp_breakdown": {"API1": 3, "API9": 2},
            },
            inventory=[
                {
                    "method": "GET",
                    "norm_path": "/api/v1/orders/{id}",
                    "classification": "documented",
                    "owasp_category": "",
                    "hit_count": 25,
                    "users_seen": ["alice", "bob"],
                },
                {
                    "method": "GET",
                    "norm_path": "/api/v1/admin/export",
                    "classification": "shadow",
                    "owasp_category": "API9",
                    "hit_count": 5,
                    "users_seen": ["alice"],
                },
            ],
            alerts=[
                {
                    "id": "alert-1",
                    "ts": "2026-11-09T10:00:00Z",
                    "type": "BOLA",
                    "severity": "HIGH",
                    "owasp_category": "API1",
                    "user": "alice",
                    "endpoint": "/api/v1/orders/{id}",
                    "explanation": "User alice accessed object 201 belonging to bob",
                }
            ],
            blocked_requests=[
                {
                    "id": "blocked-1",
                    "time": "2026-11-09T10:05:00Z",
                    "user": "alice",
                    "method": "GET",
                    "path": "/api/v1/orders/201",
                    "object_id": "201",
                    "reason": "BOLA violation",
                    "owasp_category": "API1",
                }
            ],
            enforcement_mode=True,
        )
        assert isinstance(pdf, bytes)
        assert pdf.startswith(b"%PDF-")
        assert len(pdf) > 5000


# ---------------------------------------------------------------------------
# 2. Export Tests
# ---------------------------------------------------------------------------

class TestExports:
    def test_export_alerts_csv_masks_pii(self):
        alerts = [
            {
                "id": "a-1",
                "ts": "2026-11-09T12:00:00Z",
                "type": "BOLA",
                "severity": "HIGH",
                "owasp_category": "API1",
                "user": "alice",
                "endpoint": "/api/v1/orders/{id}",
                "object_id": "201",
                "method": "GET",
                "status": 200,
                "explanation": "User alice@example.com accessed card 4111-2222-3333-4444",
                "remediation": "Call support at 555-123-4567 for fix",
            }
        ]
        csv_out = export_alerts_csv(alerts)
        assert "Alert ID,Timestamp,Type" in csv_out
        assert "alice@example.com" not in csv_out
        assert "[EMAIL-MASKED]" in csv_out
        assert "4111-2222-3333-4444" not in csv_out
        assert "[CARD-MASKED]" in csv_out
        assert "555-123-4567" not in csv_out
        assert "[PHONE-MASKED]" in csv_out

    def test_export_alerts_json_masks_pii(self):
        alerts = [
            {
                "id": "a-1",
                "explanation": "Found token-alice in header",
                "req_body": '{"email": "bob@test.com"}',
            }
        ]
        json_str = export_alerts_json(alerts)
        data = json.loads(json_str)
        assert isinstance(data, list)
        assert "[TOKEN-MASKED]" in data[0]["explanation"]
        assert "[EMAIL-MASKED]" in data[0]["req_body"]

    def test_export_blocked_csv(self):
        blocked = [
            {
                "id": "b-1",
                "time": "2026-11-09T12:01:00Z",
                "user": "alice",
                "method": "GET",
                "path": "/api/v1/orders/201",
                "object_id": "201",
                "status": 403,
                "reason": "BOLA: Alice accessing Bob's order with token-alice",
                "owasp_category": "API1",
            }
        ]
        csv_out = export_blocked_csv(blocked)
        assert "Block ID,Timestamp,User,Method" in csv_out
        assert "b-1" in csv_out
        assert "[TOKEN-MASKED]" in csv_out

    def test_export_discovered_openapi_yaml(self):
        inventory = {
            ("GET", "/api/v1/orders"): EndpointInfo(
                method="GET",
                norm_path="/api/v1/orders",
                classification="documented",
                owasp_category="",
                hit_count=10,
            ),
            ("GET", "/api/v1/admin/export"): EndpointInfo(
                method="GET",
                norm_path="/api/v1/admin/export",
                classification="shadow",
                owasp_category="API9",
                hit_count=3,
            ),
            ("GET", "/api/v0/users"): EndpointInfo(
                method="GET",
                norm_path="/api/v0/users",
                classification="zombie",
                owasp_category="API9",
                hit_count=2,
            ),
        }
        yaml_out = export_discovered_openapi(inventory)
        parsed = yaml.safe_load(yaml_out)
        assert "paths" in parsed
        assert "/api/v1/admin/export" in parsed["paths"]
        assert "/api/v0/users" in parsed["paths"]

        # Check shadow annotation
        shadow_op = parsed["paths"]["/api/v1/admin/export"]["get"]
        assert shadow_op["x-sentinel-status"] == "shadow"
        assert shadow_op["x-sentinel-hits"] == 3

        # Check zombie annotation
        zombie_op = parsed["paths"]["/api/v0/users"]["get"]
        assert zombie_op["x-sentinel-status"] == "zombie"
        assert zombie_op["deprecated"] is True


# ---------------------------------------------------------------------------
# 3. API Endpoints Tests
# ---------------------------------------------------------------------------

class TestPhase3Endpoints:
    @pytest.fixture
    def client(self):
        app.config["TESTING"] = True
        with app.test_client() as c:
            yield c

    def test_report_pdf_endpoint(self, client):
        resp = client.get("/api/report.pdf")
        assert resp.status_code == 200
        assert resp.mimetype == "application/pdf"
        assert resp.data.startswith(b"%PDF-")
        assert "attachment" in resp.headers.get("Content-Disposition", "")

    def test_export_alerts_csv_endpoint(self, client):
        resp = client.get("/api/export/alerts.csv")
        assert resp.status_code == 200
        assert "text/csv" in resp.mimetype
        assert "Alert ID" in resp.data.decode("utf-8")

    def test_export_alerts_json_endpoint(self, client):
        resp = client.get("/api/export/alerts.json")
        assert resp.status_code == 200
        assert "application/json" in resp.mimetype
        data = resp.get_json()
        assert isinstance(data, list)

    def test_export_blocked_csv_endpoint(self, client):
        resp = client.get("/api/export/blocked.csv")
        assert resp.status_code == 200
        assert "text/csv" in resp.mimetype
        assert "Block ID" in resp.data.decode("utf-8")

    def test_export_openapi_yaml_endpoint(self, client):
        resp = client.get("/api/export/openapi.yaml")
        assert resp.status_code == 200
        data_str = resp.data.decode("utf-8")
        assert "paths:" in data_str or "openapi:" in data_str
