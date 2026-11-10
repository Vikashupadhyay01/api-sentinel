"""
attack-sim/shadow_calls.py – Exercises undocumented endpoints (Shadow & Zombie APIs).

Endpoints targeted:
  1. GET /api/v1/admin/export (Shadow API – not present in openapi/openapi.yaml)
  2. GET /api/v0/users        (Zombie API – deprecated legacy API still online)

ACCEPTANCE CRITERIA:
Sentinel flags /api/v1/admin/export as Shadow API (OWASP API9)
Sentinel flags /api/v0/users as Zombie API (OWASP API9)
"""
from __future__ import annotations

import sys
import requests

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"

def run():
    print(f"[shadow_calls] Exercising Shadow & Zombie APIs against {BASE}...\n")

    # 1. Login to obtain token
    login_resp = requests.post(f"{BASE}/api/v1/login", json={"username": "alice", "password": "alice123"})
    token = login_resp.json().get("token")
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Call Shadow API (/api/v1/admin/export)
    print("Calling Shadow API: GET /api/v1/admin/export...")
    r_shadow = requests.get(f"{BASE}/api/v1/admin/export", headers=headers)
    print(f"  Status: {r_shadow.status_code}")
    if r_shadow.status_code == 200:
        orders = r_shadow.json().get("orders", [])
        print(f"  Exfiltrated {len(orders)} order records from undocumented export endpoint!")

    # 3. Call Zombie API (/api/v0/users)
    print("\nCalling Zombie API: GET /api/v0/users (deprecated v0 endpoint)...")
    r_zombie = requests.get(f"{BASE}/api/v0/users")
    print(f"  Status: {r_zombie.status_code}")
    if r_zombie.status_code == 200:
        users = r_zombie.json()
        print(f"  Exfiltrated {len(users)} user accounts from unmaintained legacy v0 API!")

    print("\n[shadow_calls] Finished.")

if __name__ == "__main__":
    run()

