# API-Sentinel 🛡️
> **Runtime BOLA & Shadow API Detection Engine**  
> *University / Internship Lab Project — Target: Deliberately Vulnerable Mock API (Localhost Only)*

---

## 📌 Executive Summary

Modern Web Application Firewalls (WAFs) inspect standard signatures (SQLi, XSS) but are blind to business-logic flaws such as **Broken Object Level Authorization (BOLA)** and undocumented **Shadow & Zombie APIs**. 

**API-Sentinel** is a lightweight, non-intrusive runtime detection and enforcement engine. It monitors live HTTP API traffic, constructs a dynamic endpoint inventory against official OpenAPI contracts, detects cross-user data tampering in real time, applies rate-limiting and bot heuristics, masks sensitive PII, and optionally blocks attacking requests (**Enforcement Mode**).

---

## 📐 Architecture

```
   [Traffic Sources / Attackers]
                │
                ▼ :8080
    ┌──────────────────────┐        Pre-flight check (ENFORCE=1)
    │    Capture Proxy     │ ──────────────────────────────────────────┐
    │    (Flask+httpx)     │ ◀───────────────────────────────────────┐ │
    └──────────┬───────────┘        Verdict (200 OK / 403 Block)      │ │
               │                                                      │ │
               ├──────────────────────────────┐                       │ │
      Forward  │                              │ Async Write           │ │
               ▼ :8000                        ▼                       │ │
    ┌──────────────────────┐         ┌─────────────────┐              │ │
    │   Target Mock API    │         │   data/events   │              │ │
    │  (FastAPI / Flask)   │         │     .jsonl      │              │ │
    └──────────────────────┘         └────────┬────────┘              │ │
                                              │ Live Tail             │ │
                                              ▼                       │ │
                                 ┌─────────────────────────┐          │ │
                                 │   Detection Pipeline    │          │ │
                                 │  (parser -> detectors)  │          │ │
                                 └────────────┬────────────┘          │ │
                                              │ In-Memory State       │ │
                                              ▼                       │ │
                                 ┌─────────────────────────┐          │ │
                                 │  Detection API (:9000)  │ ◀────────┴─┘
                                 │  (Endpoints, Alerts)    │
                                 └────────────┬────────────┘
                                              │ Polls (every 2s)
                                              ▼ :5173
                                 ┌─────────────────────────┐
                                 │     React Dashboard     │
                                 │     (Vite + React)      │
                                 └─────────────────────────┘
```

---

## 🎯 OWASP API Security Top 10:2023 Mapping

| OWASP Category | Vulnerability Type | Detection Technique in API-Sentinel | Severity |
|---|---|---|---|
| **API1:2023** | **BOLA (Broken Object Level Authorization)** | Stateful learning of user ownership from list endpoints; flags unauthorized cross-user detail reads (`/api/v1/orders/{id}`) | **HIGH** |
| **API4:2023** | **Unrestricted Resource Consumption** | Sliding-window request counter per user / IP identity | **MEDIUM** |
| **API6:2023** | **Unrestricted Access to Sensitive Flows** | Burst heuristic for sequential numeric ID scanning / bot scraping | **HIGH** |
| **API9:2023** | **Improper Inventory Management** | Diffs traffic against `openapi/openapi.yaml`; flags **Shadow APIs** (missing from spec) and **Zombie APIs** (legacy versions e.g. `/api/v0/`) | **MEDIUM / HIGH** |

---

## 📁 Repository Structure

```
api-sentinel/
├── attack-sim/                 # Attack & traffic simulation scripts
│   ├── normal_traffic.py       # Simulates all 3 users browsing own data (0 alerts)
│   ├── bola_attack.py          # Alice accesses Bob and Carol's orders
│   ├── shadow_calls.py         # Calls undocumented /admin/export & legacy /api/v0/users
│   └── enumeration_attack.py   # Rapid ID scanning burst
├── backend/                    # Python 3.11+ Detection Engine
│   ├── parser.py               # Safe JSONL record reader with typing
│   ├── discovery.py            # Path normalizer ({id}), OpenAPI diffing & noise filter
│   ├── bola.py                 # Ownership learning & BOLA detector
│   ├── ratelimit.py            # Sliding-window rate limiter & bot heuristics
│   ├── risk.py                 # 0-100 Risk Score calculator & qualitative bands
│   ├── timeline.py             # 15-minute rolling activity timeline (10s buckets)
│   ├── users.py                # Per-user threat profiler & ranking
│   ├── remediation.py          # OWASP descriptions & actionable remediations
│   ├── report.py               # ReportLab Executive PDF report generator
│   ├── export.py               # CSV/JSON exporters & Discovered OpenAPI YAML generator
│   ├── demo_helper.py          # Localhost attack simulation & safe state reset
│   ├── pii.py                  # Credit card, token, email & phone redaction
│   ├── pipeline.py             # Event log tailer & detector coordinator
│   ├── api.py                  # Detection API (:9000) with CORS & export routes
│   └── tests/                  # 175 pytest unit tests (test_api, phase2, phase3, phase4)
├── capture/                    # Traffic capture layer
│   ├── proxy.py                # Reverse proxy on :8080 (dynamic mode polling & ENFORCE=1)
│   └── benchmark.py            # Latency overhead measurement (< 5 ms goal)
├── dashboard/                  # Frontend UI
│   ├── src/                    # React 18 + Vite dashboard (drawer, filters, gauge, timeline)
│   ├── package.json            # npm package dependencies
│   └── preview.html            # Zero-dependency browser preview with interactive controls
├── data/                       # Runtime event log (events.jsonl)
├── docs/                       # Architecture & design documentation
│   └── ARCHITECTURE.md         # Detailed technical specification
├── mock-api/                   # Deliberately vulnerable target API
│   ├── app.py                  # FastAPI target on :8000
│   └── flask_app.py            # Zero-dependency Flask fallback
├── openapi/                    # Contract definition
│   └── openapi.yaml            # Official API contract (4 documented endpoints)
├── scripts/                    # Orchestration scripts
│   └── demo.sh                 # End-to-end automated demonstration
├── conftest.py                 # Pytest configuration
└── README.md                   # Project documentation
```

---

## 🚀 Quick Start

### 1. Automated Full Demo (Recommended)

Run the end-to-end simulation script. It launches all services, runs legitimate traffic, executes attacks, verifies detection and enforcement, and outputs a complete summary:

```bash
# Standard Detection Mode (Passively flags all attacks)
./scripts/demo.sh

# Active Enforcement Mode (Blocks BOLA & rate-limit violations with HTTP 403)
ENFORCE=1 ./scripts/demo.sh
```

---

### 2. Manual Component-by-Component Execution

#### Terminal 1 — Target Mock API
```bash
python3 mock-api/flask_app.py
# (Or using FastAPI: uvicorn mock-api.app:app --port 8000)
```

#### Terminal 2 — Detection API & Pipeline
```bash
python3 backend/api.py
```

#### Terminal 3 — Capture Proxy
```bash
# Detection Mode:
python3 capture/proxy.py

# Active Enforcement Mode:
ENFORCE=1 python3 capture/proxy.py
```

#### Terminal 4 — Dashboard
```bash
# Option A: React + Vite dev server
cd dashboard && npm install && npm run dev

# Option B: Direct browser preview (no npm install required)
# Open dashboard/preview.html in your browser!
```

#### Terminal 5 — Traffic & Attack Simulations
```bash
# 1. Normal traffic (zero false positives):
python3 attack-sim/normal_traffic.py

# 2. Shadow & Zombie API discovery:
python3 attack-sim/shadow_calls.py

# 3. BOLA attack:
python3 attack-sim/bola_attack.py

# 4. Rapid ID enumeration attack:
python3 attack-sim/enumeration_attack.py
```

---

---

## 🌟 v1.1 Upgrade Highlights

1. **Bug 1 Fixed (Blocked Requests Source of Truth):**
   - Eliminated count vs list length discrepancy by establishing `GLOBAL_STATE.blocked_requests` as the single shared source of truth between `/api/stats` and `/api/blocked`.
   - Verified via unit test `test_blocked_count_equals_list_length_source_of_truth`.
2. **Bug 2 Fixed (Noise Filtering in Discovery):**
   - Added configurable ignore list (`/`, `/favicon.ico`, `/robots.txt`, `/static/*`, `/api/health`).
   - Only endpoints matching `/api/*` are treated as inventory candidates.
3. **Executive PDF Security Report (`/api/report.pdf`):**
   - High-fidelity PDF report built server-side via ReportLab.
   - Includes formal cover page, executive summary with risk gauge, OWASP category breakdown table + bar chart, endpoint inventory, audit logs, top 5 findings with actionable remediation advice, and dynamic `"Page X of Y"` two-pass `NumberedCanvas`.
4. **Data & OpenAPI Contract Export:**
   - One-click CSV and JSON exports for alerts (`/api/export/alerts.csv`, `alerts.json`) and blocked requests (`/api/export/blocked.csv`).
   - Discovered OpenAPI YAML export (`/api/export/openapi.yaml`) with `x-sentinel-status: shadow/zombie` tags.
5. **Dynamic Risk Score Engine (0–100):**
   - Weighted score formula incorporating severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), inventory state (`Zombie`, `Shadow`), and blocked requests.
   - Qualitative risk badges: `LOW` (0–24), `MEDIUM` (25–49), `HIGH` (50–74), `CRITICAL` (75–100).
6. **Activity Timeline (15-Minute Window):**
   - Rolling 90 10-second buckets tracking requests, alerts, and blocks.
7. **Threat Profiling by User Identity:**
   - Aggregates behavioral risk per user (`alert_count`, `blocked_count`, `top_threat`).
8. **Slide-Over Alert Details Drawer:**
   - Inspect individual alerts with threat explanation, OWASP definitions, raw PII-masked request/response payloads, and remediation guidance.
9. **Multi-Dimensional Filters & Search:**
   - On Endpoints, Alerts, and Blocked tabs (search query, severity, OWASP category, user, HTTP method).
10. **Runtime Mode Toggle & Demo Control:**
    - Live switching between `PASSIVE` and `ENFORCE` via `/api/mode` without restarting services.
    - Safe in-dashboard attack simulations (`/api/demo/attack`) restricted strictly to `127.0.0.1:8080`.
    - Live toast notifications and unread alert badge counter.

---

## 🧪 Testing & Verification

Run the comprehensive unit test suite:
```bash
python3 -m pytest backend/tests/ -v
```
**Results:** `175 passed in 1.28s` covering parser, path normalization, noise filtering, OpenAPI classification, BOLA true/false positives, rate limiting, PII masking, PDF reporting, export routes, risk scoring, timeline tracking, and demo safety controls.

Measure proxy overhead:
```bash
python3 capture/benchmark.py
```
**Results:** Proxy added latency median is **< 3 ms** (well below the < 5 ms goal).

---

## 🔒 Security Note
* The Mock API contains deliberately planted vulnerabilities for academic and demonstration purposes.
* All components run strictly on `localhost` (plain HTTP).
* No actual secrets or production credentials are present.

---
## Team
| Member | GitHub | Branch | Area |
|---|---|---|---|
| Member 3 | @Chris301-droid | `m3-parser` | Parser, shadow API discovery |

