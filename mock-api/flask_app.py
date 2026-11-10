"""
mock-api/flask_app.py – Flask-based fallback for the Mock Shop API.

Use this when FastAPI / uvicorn are not installed.  Behaviour is
identical to app.py but powered by Flask (which IS available on this system).

Planted flaws (identical to app.py – do NOT fix them):
  1. BOLA   : GET /api/v1/orders/{id} never checks who owns the order.
  2. Shadow : /api/v1/admin/export exists but NOT in openapi/openapi.yaml.
  3. Zombie : /api/v0/users is an old, deprecated endpoint still running.

Run:
  cd mock-api && python flask_app.py          # listens on :8000
  MOCK_API_PORT=8000 python mock-api/flask_app.py
"""
from __future__ import annotations

import os
from flask import Flask, jsonify, request

PORT = int(os.getenv("MOCK_API_PORT", "8000"))

# ---------------------------------------------------------------------------
# Shared in-memory data
# ---------------------------------------------------------------------------
USERS = {
    "alice": {"id": 1, "password": "alice123", "email": "alice@example.com"},
    "bob":   {"id": 2, "password": "bob123",   "email": "bob@example.com"},
    "carol": {"id": 3, "password": "carol123", "email": "carol@example.com"},
}
TOKENS = {f"token-{name}": name for name in USERS}  # token-alice -> alice

ORDERS = {
    101: {"id": 101, "owner_id": 1, "item": "Laptop",  "amount": 55000, "card_last4": "4242"},
    102: {"id": 102, "owner_id": 1, "item": "Mouse",   "amount": 800,   "card_last4": "4242"},
    201: {"id": 201, "owner_id": 2, "item": "Phone",   "amount": 30000, "card_last4": "1111"},
    202: {"id": 202, "owner_id": 2, "item": "Earbuds", "amount": 2500,  "card_last4": "1111"},
    301: {"id": 301, "owner_id": 3, "item": "Monitor", "amount": 15000, "card_last4": "9999"},
}

app = Flask(__name__)


def _current_user():
    """Resolve the bearer token; return (username, user_dict) or (None, None)."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, None
    name = TOKENS.get(auth.split(" ", 1)[1])
    if not name:
        return None, None
    return name, USERS[name]


# ---------- DOCUMENTED endpoints (listed in openapi/openapi.yaml) ----------

@app.post("/api/v1/login")
def login():
    body = request.get_json(force=True) or {}
    u = USERS.get(body.get("username", ""))
    if not u or u["password"] != body.get("password", ""):
        return jsonify({"detail": "Bad credentials"}), 401
    return jsonify({"token": f"token-{body['username']}"})


@app.get("/api/v1/users/me")
def me():
    name, u = _current_user()
    if not name:
        return jsonify({"detail": "Missing or invalid token"}), 401
    return jsonify({"username": name, "id": u["id"], "email": u["email"]})


@app.get("/api/v1/orders")
def my_orders():
    name, u = _current_user()
    if not name:
        return jsonify({"detail": "Missing or invalid token"}), 401
    return jsonify([o for o in ORDERS.values() if o["owner_id"] == u["id"]])


@app.get("/api/v1/orders/<int:order_id>")
def get_order(order_id: int):
    name, _ = _current_user()
    if not name:
        return jsonify({"detail": "Missing or invalid token"}), 401
    order = ORDERS.get(order_id)         # BUG (BOLA): owner is never checked!
    if not order:
        return jsonify({"detail": "Order not found"}), 404
    return jsonify(order)


# ---------- UNDOCUMENTED endpoints (shadow / zombie) ----------

@app.get("/api/v1/admin/export")
def admin_export():
    """Shadow API – NOT in openapi/openapi.yaml."""
    name, _ = _current_user()
    if not name:
        return jsonify({"detail": "Missing or invalid token"}), 401
    return jsonify({"orders": list(ORDERS.values())})


@app.get("/api/v0/users")
def old_users():
    """Zombie API – old deprecated version endpoint."""
    return jsonify([{"id": u["id"], "email": u["email"]} for u in USERS.values()])


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print(f"Mock Shop API (Flask) listening on http://127.0.0.1:{PORT}")
    print("DELIBERATELY VULNERABLE – lab use only")
    app.run(host="127.0.0.1", port=PORT, threaded=True, debug=False)

