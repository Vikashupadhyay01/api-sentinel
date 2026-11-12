# API-Sentinel Architecture & Engineering Specification

## 1. System Overview

API-Sentinel is a runtime security engine that passively inspects API traffic, discovers live endpoints, flags undocumented Shadow & Zombie APIs against OpenAPI contracts, detects Broken Object Level Authorization (BOLA), applies rate-limiting and bot heuristics, masks sensitive PII, and optionally blocks violating requests before they hit upstream services.

```
+-----------------------------------------------------------------------------------+
|                                  API-SENTINEL                                     |
+-----------------------------------------------------------------------------------+
                                                                                     
  [Client / Attacker]                                                               
          │                                                                         
          ▼ :8080                                                                   
  ┌─────────────────┐       Pre-flight check (ENFORCE=1)                            
  │  Capture Proxy  │ ─────────────────────────────────────────┐                    
  │ (Flask + httpx) │ ◀──────────────────────────────────────┐ │                    
  └────────┬────────┘       Verdict (200 OK / 403 Block)     │ │                    
           │                                                 │ │                    
           ├─────────────────────────────┐                   │ │                    
  Forward  │                             │ Async Append      │ │                    
           ▼ :8000                       ▼                   │ │                    
  ┌─────────────────┐            ┌───────────────┐           │ │                    
  │ Target Mock API │            │  data/events  │           │ │                    
  │  (FastAPI/Flask)│            │    .jsonl     │           │ │                    
  └─────────────────┘            └───────┬───────┘           │ │                    
                                         │ Live Tail         │ │                    
                                         ▼                   │ │                    
                             ┌───────────────────────┐       │ │                    
                             │  Detection Pipeline   │       │ │                    
                             │ (parser -> detectors) │       │ │                    
                             └───────────┬───────────┘       │ │                    
                                         │ Updates State     │ │                    
                                         ▼                   │ │                    
                             ┌───────────────────────┐       │ │                    
                             │ Detection API (:9000) │ ◀─────┴─┘                    
                             │  (Flask / FastAPI)    │                              
                             └───────────┬───────────┘                              
                                         │ Polls /api/* (2s)                        
                                         ▼ :5173                                    
                             ┌───────────────────────┐                              
                             │    React Dashboard    │                              
                             │    (Vite / React)     │                              
                             └───────────────────────┘                              
```

---

## 2. Core Components

### 2.1 Target Mock API (`mock-api/`)
* **Host & Port:** `http://127.0.0.1:8000`
* **Technology:** FastAPI (with zero-dependency Flask fallback `mock-api/flask_app.py`)
* **Data Store:** In-memory users (`alice`, `bob`, `carol`) and orders (`101`, `102` owned by Alice, `201`, `202` owned by Bob, `301` owned by Carol).
* **Planted Weaknesses:**
  1. **BOLA (OWASP API1:2023):** `GET /api/v1/orders/{order_id}` authenticates the user via bearer token (`token-<username>`), but **never checks whether the caller owns the requested order**.
  2. **Shadow API (OWASP API9:2023):** `GET /api/v1/admin/export` is live on the server, but completely missing from `openapi/openapi.yaml`.
  3. **Zombie API (OWASP API9:2023):** `GET /api/v0/users` is an old, unmaintained v0 version endpoint still running in production.

### 2.2 Capture Layer (`capture/`)
* **Host & Port:** `http://127.0.0.1:8080` (Reverse Proxy)
* **Technology:** Flask + `httpx` (connection pooled, multi-threaded)
* **Overhead:** Added latency < 5 ms median (benchmarked via `capture/benchmark.py`).
* **Format:** Emits atomic JSON Lines to `data/events.jsonl`:
  ```json
  {
    "ts": "2026-11-09T06:20:00.000Z",
    "method": "GET",
    "path": "/api/v1/orders/201",
    "query": "",
    "status": 200,
    "user": "alice",
    "req_body": "",
    "resp_body": "{\"id\":201,\"owner_id\":2}",
    "latency_ms": 2.1,
    "blocked": false
  }
  ```
* **Enforcement Mode (`ENFORCE=1`):**
  Before forwarding requests upstream to port 8000, the proxy performs a synchronous pre-flight POST to `http://127.0.0.1:9000/api/analyze`. If flagged as a BOLA or rate-limit violation, the proxy halts the request, returns `403 Forbidden` with a JSON explanation, and logs `blocked: true`.

### 2.3 Backend Engine (`backend/`)
* **Parser (`backend/parser.py`):**
  Safe JSONL streamer producing frozen `Record` dataclasses. Skips corrupt lines without halting.
* **Discovery & Inventory (`backend/discovery.py`):**
  - **Path Normalization:** Converts concrete numeric IDs and UUIDs into parameter templates (`/api/v1/orders/101` -> `/api/v1/orders/{id}`).
  - **Contract Diffing:** Loads `openapi/openapi.yaml` and classifies each observed endpoint as `documented`, `shadow` (unlisted), or `zombie` (deprecated version prefix such as `/api/v0/`).
  - **Noise Filtering (Bug 2 Fix):** Non-API noise (such as `/`, `/favicon.ico`, `/robots.txt`, `/static/*`, `/api/health`) is excluded via `is_ignored_path()`. Only paths starting with `/api/` are considered inventory candidates via `is_inventory_candidate()`.
  - **OWASP Mapping:** Shadow and Zombie APIs are categorized under **OWASP API9:2023 Improper Inventory Management**.
* **BOLA Detection (`backend/bola.py`):**
  - **Stateful Heuristic:** Learns resource ownership dynamically by inspecting array responses from list endpoints (e.g. `GET /api/v1/orders`).
  - **Cross-User Access Auditing:** Emits `HIGH` severity alerts mapped to **OWASP API1:2023 Broken Object Level Authorization** when user A attempts to read an object ID belonging to user B, or accessing arbitrary IDs never seen in their own list responses.
* **Rate Limiting & Bot Detection (`backend/ratelimit.py`):**
  - **Sliding Window:** Per-user/IP sliding window with timestamp eviction. Triggers **OWASP API4:2023 Unrestricted Resource Consumption** when thresholds are exceeded.
  - **Enumeration Heuristics:** Detects rapid bursts of sequential distinct numeric IDs on the same endpoint pattern, flagging **OWASP API6:2023 Unrestricted Access to Sensitive Business Flows**.
* **Risk Engine (`backend/risk.py`):**
  - Computes a dynamic composite Risk Score (0–100) based on weighted security findings:
    - `CRITICAL` Alert: 25 pts each
    - `HIGH` Alert: 20 pts each
    - `MEDIUM` Alert: 10 pts each
    - `LOW` Alert: 2 pts each
    - Zombie Endpoint: 15 pts each
    - Shadow Endpoint: 10 pts each
    - Blocked Request: 5 pts each (capped at 20 pts)
  - Qualitative bands: `LOW` (0–24, Emerald), `MEDIUM` (25–49, Amber), `HIGH` (50–74, Orange), `CRITICAL` (75–100, Rose/Red).
* **Timeline Activity Tracker (`backend/timeline.py`):**
  - Maintains a 15-minute rolling window partitioned into 90 discrete 10-second buckets.
  - Concurrently tallies total requests, security alerts, and blocked attempts for real-time visualization.
* **User Threat Profiling (`backend/users.py`):**
  - Aggregates behavioral risk profiles per authenticated user / identity.
  - Tracks total alerts triggered, requests blocked, and primary threat classification.
* **Remediation & OWASP Definitions (`backend/remediation.py`):**
  - Supplies contextual OWASP definitions and actionable remediation guidance tailored to each security finding.
* **Executive PDF Report Generator (`backend/report.py`):**
  - Server-side generation using ReportLab (`GET /api/report.pdf`).
  - Features a formal cover page, executive summary with risk gauge, OWASP category breakdown table and visual distribution bars, endpoint inventory table, complete alerts audit log, blocked requests log, top 5 prioritized findings with remediation steps, and dynamic `"Page X of Y"` two-pass `NumberedCanvas`.
* **Data & Contract Exporters (`backend/export.py`):**
  - `GET /api/export/alerts.csv` & `alerts.json`: Full alerts log with PII redaction.
  - `GET /api/export/blocked.csv`: Blocked requests audit trail.
  - `GET /api/export/openapi.yaml`: Enriched OpenAPI 3.0 specification incorporating discovered shadow and zombie endpoints annotated with `x-sentinel-status` vendor tags.
* **Demo Controller & Safety Harness (`backend/demo_helper.py`):**
  - `POST /api/demo/attack`: Triggers targeted traffic simulations (`bola`, `enumeration`, `shadow`, `normal`, `all`).
  - **Strict Host Verification:** Targets are validated against `ALLOWED_HOSTS = {"127.0.0.1", "localhost"}` and `ALLOWED_PORTS = {8080, 8000}`. Any external host or port is rejected with HTTP 400.
  - `POST /api/demo/reset`: Atomically flushes in-memory pipeline state and truncates `data/events.jsonl`.
* **PII Redaction (`backend/pii.py`):**
  - Irreversible pattern replacement for 16-digit credit cards (`[CARD-MASKED]`), bearer tokens (`[TOKEN-MASKED]`), emails (`[EMAIL-MASKED]`), and telephone numbers (`[PHONE-MASKED]`).
* **Detection API (`backend/api.py`):**
  - Listens on port `9000` with CORS restricted to `http://localhost:5173`.
  - Exposes `GET /api/health`, `GET /api/endpoints`, `GET /api/alerts`, `GET /api/blocked`, `GET /api/stats`, `GET /api/timeline`, `GET /api/top-users`, `GET/POST /api/mode`, `POST /api/analyze`, `GET /api/report.pdf`, `GET /api/export/*`, and `POST /api/demo/*`.
  - **Shared Source of Truth (Bug 1 Fix):** Both `/api/stats` (count) and `/api/blocked` (list) query `GLOBAL_STATE.blocked_requests`, guaranteeing count == list length.

### 2.4 React Dashboard (`dashboard/`)
* **Host & Port:** `http://localhost:5173` (Vite dev server) + standalone `dashboard/preview.html`
* **Features:**
  - 2-second live polling with engine status indicator.
  - High-level KPI stat cards (Requests, Endpoints, Alerts, Blocked).
  - Risk Score semi-circular gauge and OWASP API Security Top 10 threat distribution bar chart.
  - 15-minute rolling timeline activity bar chart with hover tooltips.
  - Top Suspicious Users risk ranking table.
  - Interactive multi-dimensional filtering and search across Endpoints, Alerts, and Blocked tabs.
  - Slide-over Alert Details Drawer displaying full threat explanation, OWASP reference, raw PII-masked request/response payloads, and remediation guidance.
  - Dynamic Runtime Mode toggle pill (`PASSIVE` ↔ `ENFORCE`) without restarting services.
  - Quick-action "Demo Attacks" dropdown and clean "Reset" button.
  - Live toast notifications on newly detected security threats and unread badge counter.
  - Direct downloads for PDF report, CSV/JSON alerts, CSV blocked log, and discovered OpenAPI YAML.

### 2.5 eBPF Kernel Sniffer (`sniffer/` - Stretch Goal)
* Documented in [`sniffer/SNIFFER_README.md`](../sniffer/SNIFFER_README.md).
* Outlines a kernel-space XDP/TC capture hook using Rust + Aya that perf-maps TCP packets to user space with sub-microsecond overhead.

