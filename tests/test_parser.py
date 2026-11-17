"""
Tests for backend/parser.py on m3-parser — M3 Week 2 work.

What this tests (and only this):
  * Part 2 raw-bytes parser: parse_request / parse_response / pair_events
  * HttpRequest.endpoint normalisation (v4): numeric + UUID -> {id},
    trailing slash stripped, /users/me unchanged
  * The bridge record_to_event: main's JSONL Record -> ApiEvent,
    bodies preserved, _try_json dict-only
  * Parser -> discovery integration at the data level only: parsed
    events grouped by normalised endpoint, checked against the
    official OpenAPI contract list. It does NOT re-implement
    discovery.classify — shadow vs zombie classification stays
    in Vikash's backend/discovery.py on main, which this file
    never touches.

Run from the repo root:
    python3 -m unittest tests.test_parser -v
  or directly:
    python3 tests/test_parser.py
"""

import json
import os
import sys
import unittest

# Allow running as `python3 tests/test_parser.py` from anywhere:
# repo root is the parent of this file's folder.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.parser import (  # noqa: E402
    HttpRequest,
    load_records,
    pair_events,
    parse_line,
    parse_request,
    parse_response,
    record_to_event,
)

# Official OpenAPI contract, exactly as on main:
# /api/v1/login, /users/me, /orders, /orders/{order_id}
# — in traffic the /orders entries appear under the /api/v1
# prefix, so their normalised forms are /api/v1/orders and
# /api/v1/orders/{id} below.
OFFICIAL_ENDPOINTS = {
    ("GET", "/api/v1/login"),
    ("POST", "/api/v1/login"),
    ("GET", "/users/me"),
    ("GET", "/api/v1/orders"),
    ("POST", "/api/v1/orders"),
    ("GET", "/api/v1/orders/{id}"),
}


def _jsonl_line(**fields):
    base = {
        "ts": "2026-11-10T10:00:00+00:00",
        "method": "GET",
        "path": "/api/v1/orders/101",
        "query": "",
        "status": 200,
        "user": "alice",
        "req_body": "",
        "resp_body": '{"order_id": 101, "user_id": "alice"}',
        "latency_ms": 12.5,
        "blocked": False,
    }
    base.update(fields)
    return json.dumps(base)


class TestEndpointNormalisation(unittest.TestCase):
    def test_numeric_id_becomes_placeholder(self):
        req = HttpRequest(method="GET", path="/api/v1/orders/101")
        self.assertEqual(req.endpoint, "/api/v1/orders/{id}")

    def test_uuid_becomes_placeholder(self):
        req = HttpRequest(
            method="GET",
            path="/api/v1/users/550e8400-e29b-41d4-a716-446655440000",
        )
        self.assertEqual(req.endpoint, "/api/v1/users/{id}")

    def test_trailing_slash_stripped(self):
        req = HttpRequest(method="GET", path="/api/v1/orders/101/")
        self.assertEqual(req.endpoint, "/api/v1/orders/{id}")

    def test_users_me_unchanged(self):
        req = HttpRequest(method="GET", path="/users/me")
        self.assertEqual(req.endpoint, "/users/me")


class TestRawBytesParser(unittest.TestCase):
    def test_parse_request(self):
        raw = (
            b"GET /api/v1/orders/101?verbose=1 HTTP/1.1\r\n"
            b"Host: localhost:8000\r\nX-User-Id: user-1\r\n\r\n"
        )
        req = parse_request(raw)
        self.assertEqual(req.method, "GET")
        self.assertEqual(req.path, "/api/v1/orders/101")
        self.assertEqual(req.endpoint, "/api/v1/orders/{id}")
        self.assertEqual(req.user_id, "user-1")
        self.assertEqual(req.query, {"verbose": ["1"]})

    def test_parse_request_bearer_user(self):
        raw = (
            b"GET /users/me HTTP/1.1\r\n"
            b"Authorization: Bearer alice\r\n\r\n"
        )
        self.assertEqual(parse_request(raw).user_id, "alice")

    def test_parse_response(self):
        raw = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
            b'{"order_id": 101}'
        )
        resp = parse_response(raw)
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.json_body, {"order_id": 101})

    def test_malformed_request_line_raises(self):
        with self.assertRaises(ValueError):
            parse_request(b"BADLINE\r\nHost: x\r\n\r\n")

    def test_malformed_status_line_raises(self):
        with self.assertRaises(ValueError):
            parse_response(b"HTTP/1.1 NOTASTATUS\r\n\r\n")

    def test_pair_events(self):
        req_raw = (
            b"GET /api/v1/orders/101 HTTP/1.1\r\n"
            b"X-User-Id: user-1\r\n\r\n"
        )
        resp_raw = b"HTTP/1.1 200 OK\r\n\r\n{}"
        event = pair_events(req_raw, resp_raw)
        self.assertEqual(event.request.endpoint, "/api/v1/orders/{id}")
        self.assertEqual(event.response.status, 200)
        self.assertEqual(event.request.user_id, "user-1")


class TestRecordBridge(unittest.TestCase):
    def test_record_to_event_preserves_bodies(self):
        rec = parse_line(_jsonl_line())
        self.assertIsNotNone(rec)
        event = record_to_event(rec)
        self.assertEqual(event.request.endpoint, "/api/v1/orders/{id}")
        self.assertEqual(event.request.user_id, "alice")
        self.assertEqual(event.response.status, 200)
        self.assertEqual(
            event.response.body, b'{"order_id": 101, "user_id": "alice"}'
        )
        self.assertEqual(
            event.response.json_body, {"order_id": 101, "user_id": "alice"}
        )

    def test_json_list_body_is_not_a_dict(self):
        rec = parse_line(_jsonl_line(resp_body="[1, 2, 3]"))
        event = record_to_event(rec)
        self.assertIsNone(event.response.json_body)
        self.assertEqual(event.response.body, b"[1, 2, 3]")


class TestParserToDiscoveryIntegration(unittest.TestCase):
    """Parsed events -> normalised endpoints -> contract check.

    No classification here: an observed endpoint simply is, or is
    not, in the official contract. Shadow/zombie labelling is
    discovery.py's job on main.
    """

    def test_observed_endpoints_against_contract(self):
        lines = [
            _jsonl_line(path="/api/v1/orders/101"),
            _jsonl_line(path="/api/v1/orders/102", user="bob"),
            _jsonl_line(
                path="/api/v1/admin/export", method="GET", user="alice"
            ),
            _jsonl_line(path="/api/v0/users", method="GET", user="alice"),
            _jsonl_line(path="/users/me", method="GET", user="alice"),
        ]
        events = [record_to_event(parse_line(line)) for line in lines]
        observed = {
            (e.request.method, e.request.endpoint) for e in events
        }
        # Documented endpoints are in the contract.
        self.assertIn(("GET", "/api/v1/orders/{id}"), observed)
        self.assertIn(("GET", "/users/me"), observed)
        # These two are observed but NOT in the official contract.
        # (Whether each is shadow or zombie is for discovery.py.)
        self.assertIn(("GET", "/api/v1/admin/export"), observed)
        self.assertIn(("GET", "/api/v0/users"), observed)
        self.assertNotIn(
            ("GET", "/api/v1/admin/export"), OFFICIAL_ENDPOINTS
        )
        self.assertNotIn(("GET", "/api/v0/users"), OFFICIAL_ENDPOINTS)
        # load_records skips the bad line, so only real events count.
        self.assertEqual(len(events), 5)

    def test_load_records_skips_malformed_lines(self):
        import tempfile

        with tempfile.NamedTemporaryFile(
            "w", suffix=".jsonl", delete=False
        ) as fh:
            fh.write(_jsonl_line() + "\n")
            fh.write('{"bad": 1}\n')
            fh.write("\n")
            tmp = fh.name
        try:
            self.assertEqual(len(load_records(tmp)), 1)
        finally:
            os.unlink(tmp)


if __name__ == "__main__":
    unittest.main(verbosity=2)
