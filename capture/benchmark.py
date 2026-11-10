"""
capture/benchmark.py – latency benchmark for the capture proxy.

Measures the median added overhead of routing requests through the proxy on
:8080 versus hitting the mock API on :8000 directly.

Usage
-----
  # Both servers must be running first:
  #   python mock-api/app.py         (or: cd mock-api && uvicorn app:app --port 8000)
  #   python capture/proxy.py        (starts on :8080)
  #
  # Then run from repo root:
  python capture/benchmark.py

Output example
--------------
  Warmup done (10 reqs each).
  Measuring 200 requests per target…

  --- Results (n=200 per target) ---
  Direct   p50= 1.23 ms  p95= 3.45 ms  p99= 6.78 ms
  Proxy    p50= 2.10 ms  p95= 5.12 ms  p99= 9.01 ms
  Overhead p50=+0.87 ms  (goal: < 5 ms)  ✓ PASS
"""

from __future__ import annotations

import statistics
import sys
import time
from typing import Sequence

import httpx

DIRECT_URL = "http://127.0.0.1:8000"
PROXY_URL = "http://127.0.0.1:8080"
WARMUP = 10
N = 200  # requests per target

# Use Alice's token for a valid authenticated request
HEADERS = {"Authorization": "Bearer token-alice"}
ENDPOINT = "/api/v1/orders"  # a lightweight GET


def _measure(base_url: str, n: int, label: str) -> list[float]:
    """Send *n* requests to *base_url* and return latencies in milliseconds."""
    latencies: list[float] = []
    with httpx.Client(base_url=base_url, timeout=10.0) as client:
        # Warmup – prime connection pools and OS socket state
        for _ in range(WARMUP):
            client.get(ENDPOINT, headers=HEADERS)
        print(f"  [{label}] Warmup done.", flush=True)

        for _ in range(n):
            t0 = time.perf_counter()
            resp = client.get(ENDPOINT, headers=HEADERS)
            elapsed = (time.perf_counter() - t0) * 1000.0
            latencies.append(elapsed)
            if resp.status_code not in (200, 404):
                print(f"  [{label}] Unexpected status {resp.status_code}", file=sys.stderr)

    return latencies


def _percentile(data: Sequence[float], pct: int) -> float:
    """Return the *pct*-th percentile of *data* (sorted copy)."""
    s = sorted(data)
    # Linear interpolation between nearest ranks
    if not s:
        return 0.0
    idx = max(0, min(len(s) - 1, int(len(s) * pct / 100)))
    return s[idx]


def main() -> None:
    print(f"Benchmarking: direct={DIRECT_URL}  proxy={PROXY_URL}")
    print(f"Endpoint: {ENDPOINT}  Warmup: {WARMUP}  Samples: {N}\n")

    direct_latencies = _measure(DIRECT_URL, N, "direct")
    proxy_latencies = _measure(PROXY_URL, N, "proxy ")

    d_p50 = _percentile(direct_latencies, 50)
    d_p95 = _percentile(direct_latencies, 95)
    d_p99 = _percentile(direct_latencies, 99)

    p_p50 = _percentile(proxy_latencies, 50)
    p_p95 = _percentile(proxy_latencies, 95)
    p_p99 = _percentile(proxy_latencies, 99)

    overhead_p50 = p_p50 - d_p50

    print(f"\n--- Results (n={N} per target) ---")
    print(f"Direct   p50={d_p50:6.2f} ms  p95={d_p95:6.2f} ms  p99={d_p99:6.2f} ms")
    print(f"Proxy    p50={p_p50:6.2f} ms  p95={p_p95:6.2f} ms  p99={p_p99:6.2f} ms")

    goal_met = overhead_p50 < 5.0
    status = "✓ PASS" if goal_met else "✗ FAIL (goal: < 5 ms)"
    print(f"Overhead p50=+{overhead_p50:.2f} ms  (goal: < 5 ms)  {status}")

    print(
        f"\nMean  direct={statistics.mean(direct_latencies):.2f} ms  "
        f"proxy={statistics.mean(proxy_latencies):.2f} ms"
    )

    sys.exit(0 if goal_met else 1)


if __name__ == "__main__":
    main()
