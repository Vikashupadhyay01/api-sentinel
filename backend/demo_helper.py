"""
backend/demo_helper.py – Safe interactive attack simulator and reset engine for API-Sentinel.

SAFETY CONSTRAINTS:
  - TARGET STRICTLY ENFORCED: Must be http://127.0.0.1:8080 or http://localhost:8080.
  - Rejects any external or non-localhost target with an immediate ValueError.
  - Educational / university lab use only.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

ALLOWED_HOSTS = {"127.0.0.1", "localhost"}
ALLOWED_PORTS = {8080, 8000}


def _validate_target_url(target: str) -> str:
    """Validate that the target URL strictly points to the local proxy/mock."""
    target = target.strip()
    parsed = urlparse(target)

    if parsed.scheme not in ("http", ""):
        raise ValueError("Only plain HTTP localhost targets are permitted in this lab.")

    hostname = parsed.hostname or "127.0.0.1"
    port = parsed.port or 8080

    if hostname not in ALLOWED_HOSTS or port not in ALLOWED_PORTS:
        raise ValueError(
            f"Security Violation: Target host '{hostname}:{port}' is rejected. "
            "API-Sentinel demo helper is strictly restricted to localhost:8080."
        )

    return f"http://{hostname}:{port}"


def run_demo_attack(attack_type: str, target: str = "http://127.0.0.1:8080") -> dict[str, Any]:
    """Execute selected attack scenario against local capture proxy."""
    base = _validate_target_url(target)
    attack_type = attack_type.lower().strip()
    results: list[dict[str, Any]] = []

    client = httpx.Client(base_url=base, timeout=5.0)

    try:
        if attack_type in ("normal", "all"):
            # Normal benign traffic
            for u in ("alice", "bob", "carol"):
                # Login
                login_r = client.post("/api/v1/login", json={"username": u, "password": f"{u}123"})
                token = login_r.json().get("token")
                h = {"Authorization": f"Bearer {token}"} if token else {}

                # Profile
                client.get("/api/v1/users/me", headers=h)
                # List orders
                client.get("/api/v1/orders", headers=h)

                # Own order access
                own_ids = [101, 102] if u == "alice" else [201, 202] if u == "bob" else [301]
                for oid in own_ids:
                    r = client.get(f"/api/v1/orders/{oid}", headers=h)
                    results.append({
                        "user": u,
                        "type": "NORMAL",
                        "endpoint": f"/api/v1/orders/{oid}",
                        "status": r.status_code,
                    })

        if attack_type in ("shadow", "all"):
            # Exercise shadow and zombie routes
            login_r = client.post("/api/v1/login", json={"username": "alice", "password": "alice123"})
            token = login_r.json().get("token")
            h = {"Authorization": f"Bearer {token}"} if token else {}

            # Shadow API
            r_sh = client.get("/api/v1/admin/export", headers=h)
            results.append({
                "type": "SHADOW",
                "endpoint": "/api/v1/admin/export",
                "status": r_sh.status_code,
            })

            # Zombie API
            r_zm = client.get("/api/v0/users")
            results.append({
                "type": "ZOMBIE",
                "endpoint": "/api/v0/users",
                "status": r_zm.status_code,
            })

        if attack_type in ("bola", "all"):
            # BOLA Attack: Alice accessing Bob and Carol's orders
            login_r = client.post("/api/v1/login", json={"username": "alice", "password": "alice123"})
            token = login_r.json().get("token")
            h = {"Authorization": f"Bearer {token}"} if token else {}

            # Teach Alice list first
            client.get("/api/v1/orders", headers=h)

            for target_id in (201, 202, 301):
                r_bola = client.get(f"/api/v1/orders/{target_id}", headers=h)
                results.append({
                    "user": "alice",
                    "type": "BOLA",
                    "target_object_id": target_id,
                    "endpoint": f"/api/v1/orders/{target_id}",
                    "status": r_bola.status_code,
                    "blocked": r_bola.status_code == 403,
                })

        if attack_type in ("enumeration", "all"):
            # Rapid sequential ID enumeration
            login_r = client.post("/api/v1/login", json={"username": "alice", "password": "alice123"})
            token = login_r.json().get("token")
            h = {"Authorization": f"Bearer {token}"} if token else {}

            enum_count = 0
            blocked_count = 0
            for oid in range(100, 126):
                r_enum = client.get(f"/api/v1/orders/{oid}", headers=h)
                enum_count += 1
                if r_enum.status_code == 403:
                    blocked_count += 1
                time.sleep(0.01)

            results.append({
                "type": "ENUMERATION",
                "total_probes": enum_count,
                "blocked": blocked_count,
            })

        return {
            "status": "completed",
            "attack_type": attack_type,
            "target": base,
            "probes_sent": len(results),
            "summary": results,
        }
    finally:
        client.close()

