"""
attack-sim/normal_traffic.py – Simulates legitimate traffic across all 3 users.

Each user logs in, checks /api/v1/users/me, lists their own orders, and reads
their own individual orders.
- Alice: reads orders 101, 102
- Bob: reads orders 201, 202
- Carol: reads order 301

ACCEPTANCE CRITERIA:
Running normal traffic must produce ZERO security alerts.
"""
from __future__ import annotations

import sys
import time
import requests

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"

USERS = [
    ("alice", "alice123", [101, 102]),
    ("bob", "bob123", [201, 202]),
    ("carol", "carol123", [301]),
]

def run():
    print(f"[normal_traffic] Targeting {BASE}...")
    for username, password, own_orders in USERS:
        print(f"\n--- User: {username} ---")
        
        # 1. Login
        resp = requests.post(f"{BASE}/api/v1/login", json={"username": username, "password": password})
        if resp.status_code != 200:
            print(f"  ❌ Login failed for {username}: {resp.status_code} {resp.text}")
            continue
        token = resp.json().get("token")
        headers = {"Authorization": f"Bearer {token}"}
        print(f"  ✓ Logged in as {username} (token: {token})")

        # 2. Get profile
        me_resp = requests.get(f"{BASE}/api/v1/users/me", headers=headers)
        print(f"  ✓ Profile {me_resp.status_code}: {me_resp.json().get('email')}")

        # 3. List orders (teaches ownership map to Sentinel)
        orders_resp = requests.get(f"{BASE}/api/v1/orders", headers=headers)
        orders = orders_resp.json()
        print(f"  ✓ Listed {len(orders)} owned orders")

        # 4. Access each owned order individually
        for oid in own_orders:
            detail_resp = requests.get(f"{BASE}/api/v1/orders/{oid}", headers=headers)
            print(f"  ✓ Read owned order {oid} ({detail_resp.status_code}): {detail_resp.json().get('item')}")

        time.sleep(0.1)

    print("\n[normal_traffic] Finished simulating benign traffic for all users.")

if __name__ == "__main__":
    run()

