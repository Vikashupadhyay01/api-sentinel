"""
backend/tests/test_discovery.py – unit tests for backend.discovery

Covers:
  - normalize_path: integers, UUIDs, mixed, non-ID strings untouched
  - _is_zombie_path: v0 is zombie, v1 is not, v2 is not
  - load_openapi: returns correct (method, norm_path) set from real YAML
  - load_openapi: missing file returns empty set
  - classify: documented / shadow / zombie
  - build_inventory: hit counts, first/last seen, users_seen, classification
  - inventory_to_list: JSON-serialisable, sorted
"""
from __future__ import annotations

import json
import tempfile
import textwrap
from pathlib import Path

import pytest

from backend.discovery import (
    DEFAULT_IGNORE_PATTERNS,
    EndpointInfo,
    _is_zombie_path,
    build_inventory,
    classify,
    inventory_to_list,
    is_ignored_path,
    is_inventory_candidate,
    load_openapi,
    normalize_path,
)
from backend.parser import Record


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_record(
    method: str = "GET",
    path: str = "/api/v1/orders",
    status: int = 200,
    user: str | None = "alice",
    resp_body: str = "[]",
    ts: str = "2026-11-09T05:00:00+00:00",
) -> Record:
    return Record(
        ts=ts,
        method=method,
        path=path,
        query="",
        status=status,
        user=user,
        req_body="",
        resp_body=resp_body,
        latency_ms=1.0,
        blocked=False,
    )


def _write_openapi(content: str, tmp_path: Path) -> Path:
    p = tmp_path / "openapi.yaml"
    p.write_text(textwrap.dedent(content))
    return p


# ---------------------------------------------------------------------------
# normalize_path
# ---------------------------------------------------------------------------

class TestNormalizePath:

    def test_integer_id_replaced(self):
        assert normalize_path("/api/v1/orders/101") == "/api/v1/orders/{id}"

    def test_large_integer_replaced(self):
        assert normalize_path("/api/v1/items/9999999") == "/api/v1/items/{id}"

    def test_uuid_replaced(self):
        assert normalize_path(
            "/api/v1/users/550e8400-e29b-41d4-a716-446655440000"
        ) == "/api/v1/users/{id}"

    def test_string_segment_untouched(self):
        assert normalize_path("/api/v1/users/me") == "/api/v1/users/me"
        assert normalize_path("/api/v1/admin/export") == "/api/v1/admin/export"

    def test_collection_path_untouched(self):
        assert normalize_path("/api/v1/orders") == "/api/v1/orders"

    def test_multiple_ids_in_path(self):
        assert normalize_path("/api/v1/users/5/orders/42") == "/api/v1/users/{id}/orders/{id}"

    def test_root_path(self):
        assert normalize_path("/") == "/"

    def test_no_leading_slash(self):
        # Should not crash with unusual input
        result = normalize_path("api/v1/orders/101")
        assert "{id}" in result

    def test_mixed_version_not_replaced(self):
        # "v1" should NOT be treated as an ID
        assert normalize_path("/api/v1/orders") == "/api/v1/orders"


# ---------------------------------------------------------------------------
# _is_zombie_path
# ---------------------------------------------------------------------------

class TestIsZombiePath:

    def test_v0_is_zombie(self):
        assert _is_zombie_path("/api/v0/users") is True

    def test_v1_is_not_zombie(self):
        assert _is_zombie_path("/api/v1/orders") is False

    def test_v2_is_not_zombie(self):
        # v2 is a newer version – not zombie
        assert _is_zombie_path("/api/v2/orders") is False

    def test_no_version_prefix_is_not_zombie(self):
        assert _is_zombie_path("/health") is False
        assert _is_zombie_path("/api/orders") is False


# ---------------------------------------------------------------------------
# load_openapi
# ---------------------------------------------------------------------------

SAMPLE_SPEC = """\
    openapi: 3.0.3
    info:
      title: Test API
      version: "1.0"
    paths:
      /api/v1/login:
        post:
          summary: Login
      /api/v1/users/me:
        get:
          summary: Current user
      /api/v1/orders:
        get:
          summary: List orders
      /api/v1/orders/{order_id}:
        get:
          summary: Get order
"""


class TestLoadOpenapi:

    def test_loads_correct_pairs(self, tmp_path):
        p = _write_openapi(SAMPLE_SPEC, tmp_path)
        documented = load_openapi(p)
        assert ("POST", "/api/v1/login") in documented
        assert ("GET", "/api/v1/users/me") in documented
        assert ("GET", "/api/v1/orders") in documented
        # OpenAPI template {order_id} → {id}
        assert ("GET", "/api/v1/orders/{id}") in documented

    def test_does_not_include_undocumented(self, tmp_path):
        p = _write_openapi(SAMPLE_SPEC, tmp_path)
        documented = load_openapi(p)
        assert ("GET", "/api/v1/admin/export") not in documented
        assert ("GET", "/api/v0/users") not in documented

    def test_missing_file_returns_empty(self, tmp_path):
        result = load_openapi(tmp_path / "missing.yaml")
        assert result == set()

    def test_empty_file_returns_empty(self, tmp_path):
        p = tmp_path / "empty.yaml"
        p.write_text("")
        assert load_openapi(p) == set()


# ---------------------------------------------------------------------------
# classify
# ---------------------------------------------------------------------------

class TestClassify:

    @pytest.fixture()
    def documented(self, tmp_path):
        p = _write_openapi(SAMPLE_SPEC, tmp_path)
        return load_openapi(p)

    def test_documented_endpoint(self, documented):
        assert classify("GET", "/api/v1/orders", documented) == "documented"
        assert classify("GET", "/api/v1/orders/{id}", documented) == "documented"
        assert classify("POST", "/api/v1/login", documented) == "documented"

    def test_shadow_endpoint(self, documented):
        assert classify("GET", "/api/v1/admin/export", documented) == "shadow"
        assert classify("GET", "/api/v1/unknown", documented) == "shadow"

    def test_zombie_endpoint(self, documented):
        # /api/v0/ paths are zombie regardless of spec
        assert classify("GET", "/api/v0/users", documented) == "zombie"
        assert classify("GET", "/api/v0/orders", documented) == "zombie"

    def test_zombie_takes_priority_over_documented(self, documented):
        # Even if somehow /api/v0/something were in the spec, zombie wins
        documented.add(("GET", "/api/v0/legacy"))
        assert classify("GET", "/api/v0/legacy", documented) == "zombie"


# ---------------------------------------------------------------------------
# build_inventory
# ---------------------------------------------------------------------------

class TestBuildInventory:

    def test_hit_count_accumulates(self, tmp_path):
        spec = _write_openapi(SAMPLE_SPEC, tmp_path)
        records = [
            _make_record(path="/api/v1/orders"),
            _make_record(path="/api/v1/orders"),
            _make_record(path="/api/v1/orders"),
        ]
        inv = build_inventory(records, spec_path=spec)
        info = inv[("GET", "/api/v1/orders")]
        assert info.hit_count == 3

    def test_shadow_endpoint_classified_correctly(self, tmp_path):
        spec = _write_openapi(SAMPLE_SPEC, tmp_path)
        records = [_make_record(path="/api/v1/admin/export")]
        inv = build_inventory(records, spec_path=spec)
        info = inv[("GET", "/api/v1/admin/export")]
        assert info.classification == "shadow"
        assert info.owasp_category == "API9"

    def test_zombie_endpoint_classified_correctly(self, tmp_path):
        spec = _write_openapi(SAMPLE_SPEC, tmp_path)
        records = [_make_record(path="/api/v0/users", user=None)]
        inv = build_inventory(records, spec_path=spec)
        info = inv[("GET", "/api/v0/users")]
        assert info.classification == "zombie"
        assert info.owasp_category == "API9"

    def test_documented_endpoint_classified_correctly(self, tmp_path):
        spec = _write_openapi(SAMPLE_SPEC, tmp_path)
        records = [_make_record(path="/api/v1/orders")]
        inv = build_inventory(records, spec_path=spec)
        info = inv[("GET", "/api/v1/orders")]
        assert info.classification == "documented"
        assert info.owasp_category is None

    def test_path_normalised_to_id(self, tmp_path):
        spec = _write_openapi(SAMPLE_SPEC, tmp_path)
        records = [
            _make_record(path="/api/v1/orders/101"),
            _make_record(path="/api/v1/orders/202"),  # different concrete ID, same endpoint
        ]
        inv = build_inventory(records, spec_path=spec)
        # Both should map to the same normalised key
        assert ("GET", "/api/v1/orders/{id}") in inv
        assert inv[("GET", "/api/v1/orders/{id}")].hit_count == 2

    def test_first_last_seen_populated(self, tmp_path):
        spec = _write_openapi(SAMPLE_SPEC, tmp_path)
        records = [
            _make_record(path="/api/v1/orders", ts="2026-11-09T05:00:00+00:00"),
            _make_record(path="/api/v1/orders", ts="2026-11-09T06:00:00+00:00"),
        ]
        inv = build_inventory(records, spec_path=spec)
        info = inv[("GET", "/api/v1/orders")]
        assert info.first_seen == "2026-11-09T05:00:00+00:00"
        assert info.last_seen == "2026-11-09T06:00:00+00:00"

    def test_users_seen_collected(self, tmp_path):
        spec = _write_openapi(SAMPLE_SPEC, tmp_path)
        records = [
            _make_record(path="/api/v1/orders", user="alice"),
            _make_record(path="/api/v1/orders", user="bob"),
            _make_record(path="/api/v1/orders", user="alice"),
        ]
        inv = build_inventory(records, spec_path=spec)
        assert inv[("GET", "/api/v1/orders")].users_seen == {"alice", "bob"}

    def test_status_codes_tallied(self, tmp_path):
        spec = _write_openapi(SAMPLE_SPEC, tmp_path)
        records = [
            _make_record(path="/api/v1/orders", status=200),
            _make_record(path="/api/v1/orders", status=200),
            _make_record(path="/api/v1/orders", status=401),
        ]
        inv = build_inventory(records, spec_path=spec)
        assert inv[("GET", "/api/v1/orders")].status_codes == {200: 2, 401: 1}

    def test_empty_records_returns_empty(self, tmp_path):
        spec = _write_openapi(SAMPLE_SPEC, tmp_path)
        inv = build_inventory([], spec_path=spec)
        assert inv == {}


# ---------------------------------------------------------------------------
# inventory_to_list
# ---------------------------------------------------------------------------

class TestInventoryToList:

    def test_returns_list_of_dicts(self, tmp_path):
        spec = _write_openapi(SAMPLE_SPEC, tmp_path)
        records = [_make_record(path="/api/v1/orders")]
        inv = build_inventory(records, spec_path=spec)
        result = inventory_to_list(inv)
        assert isinstance(result, list)
        assert isinstance(result[0], dict)

    def test_json_serialisable(self, tmp_path):
        spec = _write_openapi(SAMPLE_SPEC, tmp_path)
        records = [
            _make_record(path="/api/v1/orders", user="alice"),
            _make_record(path="/api/v1/admin/export", user="alice"),
        ]
        inv = build_inventory(records, spec_path=spec)
        result = inventory_to_list(inv)
        # Should not raise
        serialised = json.dumps(result)
        assert "/api/v1/orders" in serialised

    def test_sorted_by_norm_path(self, tmp_path):
        spec = _write_openapi(SAMPLE_SPEC, tmp_path)
        records = [
            _make_record(path="/api/v1/orders"),
            _make_record(path="/api/v1/admin/export"),
        ]
        inv = build_inventory(records, spec_path=spec)
        result = inventory_to_list(inv)
        paths = [r["norm_path"] for r in result]
        assert paths == sorted(paths)


# ---------------------------------------------------------------------------
# Ignore list & noise filtering tests (BUG 2)
# ---------------------------------------------------------------------------

class TestNoiseFiltering:

    def test_default_ignore_patterns_cover_expected_paths(self):
        assert "/" in DEFAULT_IGNORE_PATTERNS
        assert "/favicon.ico" in DEFAULT_IGNORE_PATTERNS
        assert "/robots.txt" in DEFAULT_IGNORE_PATTERNS
        assert "/static/*" in DEFAULT_IGNORE_PATTERNS
        assert "/api/health" in DEFAULT_IGNORE_PATTERNS

    def test_is_ignored_path(self):
        assert is_ignored_path("/") is True
        assert is_ignored_path("/favicon.ico") is True
        assert is_ignored_path("/robots.txt") is True
        assert is_ignored_path("/static/app.js") is True
        assert is_ignored_path("/static/css/style.css") is True
        assert is_ignored_path("/api/health") is True
        assert is_ignored_path("/api/health?probe=1") is True
        # Real API endpoints are NOT ignored
        assert is_ignored_path("/api/v1/orders") is False
        assert is_ignored_path("/api/v1/admin/export") is False

    def test_is_inventory_candidate_rules(self):
        # Must start with /api/
        assert is_inventory_candidate("/") is False
        assert is_inventory_candidate("/favicon.ico") is False
        assert is_inventory_candidate("/robots.txt") is False
        assert is_inventory_candidate("/index.html") is False
        assert is_inventory_candidate("/dashboard") is False
        assert is_inventory_candidate("/static/bundle.js") is False

        # /api/health is under /api/ but ignored
        assert is_inventory_candidate("/api/health") is False

        # Legitimate API endpoints are valid candidates
        assert is_inventory_candidate("/api/v1/orders") is True
        assert is_inventory_candidate("/api/v1/orders/101") is True
        assert is_inventory_candidate("/api/v1/admin/export") is True
        assert is_inventory_candidate("/api/v0/users") is True

    def test_custom_ignore_patterns(self):
        custom = ["/api/internal/*", "/custom"]
        assert is_ignored_path("/api/internal/debug", custom) is True
        assert is_inventory_candidate("/api/internal/debug", custom) is False
        # When using custom patterns, default ones aren't applied unless included
        assert is_inventory_candidate("/api/v1/orders", custom) is True

    def test_build_inventory_excludes_noise_endpoints(self, tmp_path):
        """Browser noise like / and /favicon.ico must NEVER become shadow endpoints."""
        spec = _write_openapi(SAMPLE_SPEC, tmp_path)
        records = [
            _make_record(path="/"),
            _make_record(path="/favicon.ico"),
            _make_record(path="/robots.txt"),
            _make_record(path="/static/main.js"),
            _make_record(path="/api/health"),
            _make_record(path="/api/v1/orders"),
            _make_record(path="/api/v1/admin/export"),  # real shadow API
        ]
        inv = build_inventory(records, spec_path=spec)

        # Noise endpoints must NOT exist in inventory
        assert ("GET", "/") not in inv
        assert ("GET", "/favicon.ico") not in inv
        assert ("GET", "/robots.txt") not in inv
        assert ("GET", "/static/main.js") not in inv
        assert ("GET", "/api/health") not in inv

        # Only legitimate API endpoints are present
        assert ("GET", "/api/v1/orders") in inv
        assert ("GET", "/api/v1/admin/export") in inv
        assert inv[("GET", "/api/v1/admin/export")].classification == "shadow"


