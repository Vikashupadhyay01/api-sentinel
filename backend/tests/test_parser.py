"""
backend/tests/test_parser.py – unit tests for backend.parser

Covers:
  - parse_line: valid event, all required fields
  - parse_line: missing required field → None
  - parse_line: malformed JSON → None
  - parse_line: blank / whitespace-only line → None
  - parse_line: extra unknown fields are ignored
  - parse_line: method is uppercased
  - parse_line: null user field → None in Record
  - parse_line: blocked field defaults to False
  - iter_records: non-existent file yields nothing
  - iter_records: mixed good/bad lines skips bad ones
  - Record.datetime helper
  - Record.resp_json / req_json helpers
  - load_records convenience wrapper
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from backend.parser import Record, iter_records, load_records, parse_line


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_event(**overrides) -> dict:
    """Return a minimal valid event dict, with optional field overrides."""
    base = {
        "ts": "2026-11-09T05:30:00+00:00",
        "method": "get",         # intentionally lowercase – should be uppercased
        "path": "/api/v1/orders/101",
        "query": "",
        "status": 200,
        "user": "alice",
        "req_body": "",
        "resp_body": '{"id":101,"owner_id":1}',
        "latency_ms": 3.5,
        "blocked": False,
    }
    base.update(overrides)
    return base


def _write_jsonl(events: list, tmp_path: Path) -> Path:
    """Write a list of dicts (or raw strings) to a temp JSONL file."""
    p = tmp_path / "events.jsonl"
    with p.open("w") as fh:
        for ev in events:
            if isinstance(ev, str):
                fh.write(ev + "\n")
            else:
                fh.write(json.dumps(ev) + "\n")
    return p


# ---------------------------------------------------------------------------
# parse_line tests
# ---------------------------------------------------------------------------

class TestParseLine:

    def test_valid_event_returns_record(self):
        line = json.dumps(_make_event())
        rec = parse_line(line)
        assert isinstance(rec, Record)

    def test_method_is_uppercased(self):
        line = json.dumps(_make_event(method="get"))
        rec = parse_line(line)
        assert rec is not None
        assert rec.method == "GET"

    def test_all_required_fields_present(self):
        line = json.dumps(_make_event())
        rec = parse_line(line)
        assert rec is not None
        assert rec.ts == "2026-11-09T05:30:00+00:00"
        assert rec.path == "/api/v1/orders/101"
        assert rec.status == 200
        assert rec.user == "alice"
        assert rec.latency_ms == pytest.approx(3.5)

    def test_blocked_defaults_to_false(self):
        ev = _make_event()
        del ev["blocked"]  # omit optional field
        rec = parse_line(json.dumps(ev))
        assert rec is not None
        assert rec.blocked is False

    def test_blocked_true_preserved(self):
        rec = parse_line(json.dumps(_make_event(blocked=True)))
        assert rec is not None
        assert rec.blocked is True

    def test_null_user_becomes_none(self):
        rec = parse_line(json.dumps(_make_event(user=None)))
        assert rec is not None
        assert rec.user is None

    def test_missing_required_field_returns_none(self):
        for field_name in ("ts", "method", "path", "status", "resp_body", "latency_ms"):
            ev = _make_event()
            del ev[field_name]
            assert parse_line(json.dumps(ev)) is None, \
                f"Expected None when '{field_name}' is missing"

    def test_malformed_json_returns_none(self):
        assert parse_line("{not valid json") is None
        assert parse_line("null") is None
        assert parse_line("[1,2,3]") is None

    def test_blank_line_returns_none(self):
        assert parse_line("") is None
        assert parse_line("   ") is None
        assert parse_line("\n") is None

    def test_extra_fields_are_ignored(self):
        ev = _make_event(unknown_field="surprise", another=42)
        rec = parse_line(json.dumps(ev))
        assert rec is not None   # extra fields do not cause failure

    def test_status_coerced_to_int(self):
        rec = parse_line(json.dumps(_make_event(status="404")))
        assert rec is not None
        assert rec.status == 404
        assert isinstance(rec.status, int)

    def test_latency_coerced_to_float(self):
        rec = parse_line(json.dumps(_make_event(latency_ms="2.5")))
        assert rec is not None
        assert rec.latency_ms == pytest.approx(2.5)


# ---------------------------------------------------------------------------
# Record helper property tests
# ---------------------------------------------------------------------------

class TestRecordHelpers:

    def _rec(self, **kw) -> Record:
        return parse_line(json.dumps(_make_event(**kw)))  # type: ignore[return-value]

    def test_datetime_parses_iso8601(self):
        from datetime import timezone
        rec = self._rec(ts="2026-11-09T05:30:00+00:00")
        dt = rec.datetime
        assert dt is not None
        assert dt.tzinfo is not None
        assert dt.year == 2026

    def test_datetime_returns_none_for_bad_ts(self):
        rec = self._rec(ts="not-a-date")
        assert rec.datetime is None

    def test_resp_json_parses_valid_json(self):
        rec = self._rec(resp_body='{"id": 1}')
        assert rec.resp_json == {"id": 1}

    def test_resp_json_returns_none_for_invalid(self):
        rec = self._rec(resp_body="not json")
        assert rec.resp_json is None

    def test_req_json_parses_valid_json(self):
        rec = self._rec(req_body='{"username": "alice"}')
        assert rec.req_json == {"username": "alice"}

    def test_req_json_returns_none_for_empty(self):
        rec = self._rec(req_body="")
        assert rec.req_json is None


# ---------------------------------------------------------------------------
# iter_records / load_records tests
# ---------------------------------------------------------------------------

class TestIterRecords:

    def test_nonexistent_file_yields_nothing(self, tmp_path):
        result = list(iter_records(tmp_path / "nope.jsonl"))
        assert result == []

    def test_valid_file_yields_all_records(self, tmp_path):
        events = [_make_event(path=f"/api/v1/orders/{i}") for i in range(5)]
        p = _write_jsonl(events, tmp_path)
        records = list(iter_records(p))
        assert len(records) == 5

    def test_skips_malformed_lines(self, tmp_path):
        events = [
            _make_event(),           # valid
            "GARBAGE LINE",          # malformed
            _make_event(),           # valid
            "",                      # blank
            json.dumps({"ts": "x"}), # missing fields
            _make_event(),           # valid
        ]
        p = _write_jsonl(events, tmp_path)
        records = list(iter_records(p))
        assert len(records) == 3

    def test_load_records_returns_list(self, tmp_path):
        p = _write_jsonl([_make_event(), _make_event()], tmp_path)
        records = load_records(p)
        assert isinstance(records, list)
        assert len(records) == 2

    def test_records_are_frozen(self, tmp_path):
        p = _write_jsonl([_make_event()], tmp_path)
        rec = load_records(p)[0]
        with pytest.raises((AttributeError, TypeError)):
            rec.status = 999  # type: ignore[misc]

    def test_unicode_in_resp_body(self, tmp_path):
        ev = _make_event(resp_body='{"item": "Ноутбук"}')
        p = _write_jsonl([ev], tmp_path)
        records = list(iter_records(p))
        assert records[0].resp_body == '{"item": "Ноутбук"}'

