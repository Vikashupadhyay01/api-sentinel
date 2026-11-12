"""
attack-sim/enumeration_attack.py – Rapid ID enumeration / scraping attack.

Simulates an attacker or bot iterating through sequential order IDs
(/api/v1/orders/100 ... 120) in rapid succession.

ACCEPTANCE CRITERIA:
Sentinel detects the burst of distinct numeric IDs on the same endpoint
and triggers:
  - OWASP API6: Unrestricted Access to Sensitive Business Flows (ENUMERATION)
  - OWASP API4: Unrestricted Resource Consumption (RATE_LIMIT)
"""
from __future__ import annotations

import sys
import time
import requests

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"

def run():
    print(f"[enumeration_attack] Launching rapid ID scanning against {BASE}...\n")

    # 1. Login
    login_resp = requests.post(f"{BASE}/api/v1/login", json={"username": "alice", "password": "alice123"})
    token = login_resp.json().get("token")
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Rapid sequential enumeration across IDs 100 to 125
    print("Enumerating order IDs [100..125] at high frequency...")
    hits = 0
    for oid in range(100, 126):
        r = requests.get(f"{BASE}/api/v1/orders/{oid}", headers=headers)
        if r.status_code == 200:
            hits += 1
            print(f"  [+] ID {oid}: Found (200) - item: {r.json().get('item')}")
        elif r.status_code == 403:
            print(f"  [🛡️] ID {oid}: BLOCKED (403) by API-Sentinel Enforcement!")
        elif r.status_code == 404:
            print(f"  [-] ID {oid}: Not found (404)")
        else:
            print(f"  [?] ID {oid}: HTTP {r.status_code}")
        time.sleep(0.02)  # fast burst

    print(f"\n[enumeration_attack] Completed {26} requests. Found {hits} valid records.")

if __name__ == "__main__":
    run()

