# API-Sentinel - Runtime BOLA & Shadow API Detection Engine

Axlero Solutions - Advanced Cybersecurity Engineering - Project 1
Domain: API Security & Zero-Trust Architecture

## Problem
WAFs miss business-logic attacks such as **BOLA** (Broken Object Level Authorization,
OWASP API1) and cannot see undocumented **Shadow / Zombie APIs**. API-Sentinel watches
API traffic at runtime, builds an endpoint inventory, and detects these issues.

## Architecture
```
Mock API (HTTP) --> eBPF sniffer (Rust) --> Python backend --> React dashboard
                                              |- parser.py     (rebuild request/response)
                                              |- discovery.py  (shadow API detection)
                                              |- bola.py       (BOLA heuristics)
```
More detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## Repository layout
| Folder | Purpose |
|---|---|
| `mock-api/` | Deliberately vulnerable FastAPI shop (target) |
| `openapi/` | Official API contract used to find shadow APIs |
| `sniffer/` | Rust + eBPF traffic capture |
| `backend/` | Python parser, discovery engine, BOLA engine |
| `dashboard/` | React threat dashboard |
| `attack-sim/` | Scripted BOLA attack for testing |
| `docs/` | Plan, team workflow, test results |

## Quick start
```bash
# terminal 1 - target API
cd mock-api && python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt && uvicorn app:app --port 8000

# terminal 2 - run the attack
cd attack-sim && pip install -r requirements.txt && python3 bola_attack.py
```

## Team
| Member | GitHub | Branch | Area |
|---|---|---|---|
| Team Lead | @your-username | `main` | Repo, merges, docs, review |
| Member 2 | @username | `m2-sniffer` | eBPF + Rust sniffer |
| Member 3 | @username | `m3-latency` | eBPF latency, enforcement |
| Member 4 | @username | `m4-parser` | Parser, shadow API discovery |
| Member 5 | @username | `m5-bola` | BOLA engine, rate limiting, mock API |

## Plan
See [docs/PLAN.md](docs/PLAN.md). Team workflow: [docs/GIT_WORKFLOW.md](docs/GIT_WORKFLOW.md).

> Security note: the mock API is vulnerable on purpose. Use only on localhost. Never commit secrets.
