# Project plan (Month 1)
| Week | Low-level (eBPF / Rust) | Analytics & UI (Python / React) |
|---|---|---|
| 1 | Capture HTTP traffic with eBPF (fallback: mitmproxy) | Parser that rebuilds request/response |
| 2 | OpenAPI schema generation from traffic, flag unknown endpoints | BOLA heuristics (user ID <-> object ID) |
| Mid review | Prove < 5 ms added latency | Scripted BOLA attack is detected |
| 3 | Enforcement mode: drop violating packets | Rate limiting, bot detection |
| 4 | PII masking before data reaches dashboard | Dashboard polish + OWASP API Top 10 mapping |
| Final review | Kernel-level programming demo | API security posture tool demo |
