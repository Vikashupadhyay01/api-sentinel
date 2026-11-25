# Parser - `backend/parser.py` (M3, `m3-parser`)

This parser turns captured HTTP traffic into `ApiEvent` objects that
Week 2 `discovery.py` can use. It has two parts and two inputs, but one
event shape.

## What it does

- **Part 1 - JSONL event log reader (from `main`).** Reads the event log
  written by the capture proxy, one JSON object per line, and yields typed
  `Record` objects (`parse_line`, `iter_records`, `load_records`).
  Blank lines, malformed JSON, and lines missing required fields are
  skipped, never crash the pipeline. Part 1 is `main`'s current JSONL
  reader (`c47fbe6`, 13 Nov 2026) and is unchanged on this branch.
- **Part 2 - raw-bytes parser (M3, Week 1).** Parses raw HTTP
  request/response bytes (eBPF sniffer / proxy fallback) into the same
  `ApiEvent` shape: `parse_request`, `parse_response`, `pair_events`.
  It accepts both `CRLF` (`\r\n\r\n`) and LF-only (`\n\n`) separators.
  Malformed request/status lines raise a clear `ValueError`.

## Endpoint normalisation

`HttpRequest.endpoint` groups one real endpoint's traffic together, so
`/api/v1/orders/101` and `/api/v1/orders/102` count as one endpoint:

| Raw path | Normalised endpoint |
| --- | --- |
| `/api/v1/orders/101` | `/api/v1/orders/{id}` |
| `/api/v1/users/550e8400-e29b-41d4-a716-446655440000` | `/api/v1/users/{id}` |
| `/api/v1/orders/101/` | `/api/v1/orders/{id}` |
| `/users/me` | `/users/me` (unchanged) |

Numeric path segments and UUIDs both become `{id}` (same idea as
`discovery.normalize_path` on `main`), and a trailing slash does not
create a second endpoint.

## Performance (v7, 19 Nov 2026)

A UUID is exactly 36 characters, so the UUID regex now runs only when
`len(seg) == 36`. Results are identical, with less work per event.
Measured on 40,000 mixed endpoints: 108.7 ms -> 79.2 ms (1.37x,
27% faster). Covered by self-test 7 in `backend/parser.py`.

## Who made the request

`user_id` comes from the `X-User-Id` header, or from a
`Authorization: Bearer <name>` header when `X-User-Id` is absent.

## The bridge: `Record` -> `ApiEvent`

`record_to_event` converts a `main` JSONL `Record` into the same
`ApiEvent` the raw parser produces: `ts` -> `timestamp`,
`user` -> `user_id`, bodies preserved as bytes, and JSON bodies parsed
only when they are objects (`_try_json` is dict-only - a JSON list body
stays raw bytes with `json_body` as `None`).

## Tests - how to run

From the repo root:

```
python3 -m unittest tests.test_parser -v
```

14 tests, stdlib only, in `tests/test_parser.py` on this branch. They
cover endpoint normalisation, raw-bytes parsing, malformed lines, the
`Record` bridge, and observed endpoints checked against the official
contract at the data level only. `backend/tests/test_parser.py` on
`main` covers Part 1 only; it is a different file and is untouched.

## Official contract endpoints

`/api/v1/login`, `/users/me`, `/orders`, `/orders/{order_id}`.
Observed in traffic but **not** in the contract - for example
`/api/v1/admin/export` and `/api/v0/users` - are reported as observed
endpoints only. Whether each one is shadow or zombie is
`backend/discovery.py`'s job on `main`, not this parser's.

## What this parser does not do

- No shadow/zombie classification.
- No BOLA checks.
- No change to `backend/discovery.py` or to `main`.
