# Sniffer – eBPF Kernel-Level Capture (Stretch Goal)

> **Status:** Skeleton / stretch goal. The project does **not** depend on this component.
> The primary capture layer is [`capture/proxy.py`](../capture/proxy.py) (a userspace reverse proxy).

## What is this?

This directory is a placeholder for a future Rust + [aya](https://aya-rs.dev/) eBPF programme
that would capture raw HTTP traffic at the kernel level—without any userspace proxy overhead.

### Why eBPF?

| Property | Userspace proxy (capture/) | eBPF sniffer (sniffer/) |
|---|---|---|
| Overhead | ~1–3 ms per request | Near-zero |
| Requires app config | Yes (point apps at :8080) | No |
| Works with TLS | Only for plain HTTP | Requires kernel TLS offload or plaintext |
| Complexity | Low | High |
| Production ready | ✓ | Stretch goal |

### Why this is deferred

The lab target (`mock-api`) runs plain HTTP on localhost, which makes the userspace proxy
sufficient. eBPF requires Linux kernel ≥ 5.15, `CAP_BPF` / `CAP_SYS_ADMIN`, and a full
Rust toolchain with the aya build tooling.

## Planned sketch (do not implement yet)

```
sniffer/
  Cargo.toml           workspace with two crates
  sniffer-ebpf/        the BPF programme (xdp or tc hook on lo)
    src/main.rs        parses TCP payload, extracts HTTP/1.1 verb + path
  sniffer-user/        the userspace loader
    src/main.rs        loads the BPF prog, perf-maps events -> data/events.jsonl
```

The eBPF programme would:
1. Attach to the loopback interface (`lo`) via XDP or a TC `ingress`/`egress` hook.
2. Parse the TCP payload for HTTP/1.1 request lines.
3. Write (`bpf_perf_event_output`) a compact struct `{ts, src_ip, dst_port, verb[8], path[256]}`.

The userspace loader (aya) polls the perf ring-buffer and formats events into the same
JSONL schema as the proxy capture layer, so all downstream components are unaffected.

## References

- [aya book](https://aya-rs.dev/book/)
- [aya-template](https://github.com/aya-rs/aya-template) – project scaffold
- [Linux XDP documentation](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)

