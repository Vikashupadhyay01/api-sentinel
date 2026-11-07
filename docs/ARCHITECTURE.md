# Architecture
1. **Mock API** (FastAPI, plain HTTP, port 8000) - the system being protected.
2. **Sniffer** (Rust + eBPF via `aya`) - passively captures HTTP traffic at kernel level, no code change in the API.
3. **Parser** (Python) - rebuilds request/response pairs.
4. **Discovery engine** - normalises paths, compares with `openapi/openapi.yaml`, flags shadow/zombie endpoints.
5. **BOLA engine** - learns which object IDs each user normally accesses; flags anomalies.
6. **Dashboard** (React) - shows inventory, alerts, OWASP API Top 10 mapping.
7. Later: enforcement mode (drop packets), rate limiting, PII masking.
