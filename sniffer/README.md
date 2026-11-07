# sniffer (Rust + eBPF, Week 1 - Members 2 & 3)
Goal: attach an eBPF program to kernel socket events and capture plain-HTTP traffic
of the mock API, passing it to the Python backend.

Suggested stack: Rust + the `aya` crate. Needs kernel headers and `bpf-linker`.
Start here: https://aya-rs.dev/book/

FALLBACK (do this first so the Python team is never blocked): capture traffic with
`mitmproxy` or a FastAPI middleware, then swap in eBPF when it works.
Latency target for mid review: sidecar adds < 5 ms per request.
