"""
backend/tests/test_pipeline.py – tests for Pipeline execution and event processing.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.parser import Record
from backend.pipeline import Pipeline, PipelineState


def test_pipeline_process_record():
    state = PipelineState()
    pipeline = Pipeline(spec_path="openapi/openapi.yaml", state=state)

    # 1. Normal list call
    rec1 = Record(
        ts="2026-11-09T05:00:00+00:00",
        method="GET",
        path="/api/v1/orders",
        query="",
        status=200,
        user="bob",
        req_body="",
        resp_body='[{"id": 201, "owner_id": 2}]',
        latency_ms=2.1,
    )
    alerts1 = pipeline.process_record(rec1)
    assert len(alerts1) == 0

    stats = state.to_stats()
    assert stats["total_requests"] == 1
    assert stats["documented_endpoints"] >= 1

    # 2. Shadow endpoint
    rec2 = Record(
        ts="2026-11-09T05:00:01+00:00",
        method="GET",
        path="/api/v1/admin/export",
        query="",
        status=200,
        user="alice",
        req_body="",
        resp_body='{"orders": []}',
        latency_ms=3.0,
    )
    alerts2 = pipeline.process_record(rec2)
    assert any(a["type"] == "SHADOW" for a in alerts2)

    # 3. Zombie endpoint
    rec3 = Record(
        ts="2026-11-09T05:00:02+00:00",
        method="GET",
        path="/api/v0/users",
        query="",
        status=200,
        user=None,
        req_body="",
        resp_body='[]',
        latency_ms=1.5,
    )
    alerts3 = pipeline.process_record(rec3)
    assert any(a["type"] == "ZOMBIE" for a in alerts3)

    # 4. BOLA attack by Alice on Bob's order 201
    rec4 = Record(
        ts="2026-11-09T05:00:03+00:00",
        method="GET",
        path="/api/v1/orders/201",
        query="",
        status=200,
        user="alice",
        req_body="",
        resp_body='{"id": 201, "owner_id": 2}',
        latency_ms=2.0,
    )
    alerts4 = pipeline.process_record(rec4)
    assert any(a["type"] == "BOLA" for a in alerts4)

    final_stats = state.to_stats()
    assert final_stats["total_requests"] == 4
    assert final_stats["shadow_endpoints"] == 1
    assert final_stats["zombie_endpoints"] == 1
    assert final_stats["total_alerts"] >= 3

