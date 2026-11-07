"""
Mock e-commerce API for API-Sentinel (DELIBERATELY VULNERABLE - lab use only).

Planted weaknesses (these are what API-Sentinel must detect):
  1. BOLA   : GET /api/v1/orders/{id} never checks who owns the order.
  2. Shadow : /api/v1/admin/export exists but is NOT in openapi/openapi.yaml.
  3. Zombie : /api/v0/users is an old, deprecated endpoint still running.

Runs on plain HTTP (eBPF cannot read TLS content).
Run:  uvicorn app:app --port 8000
Demo passwords below are fake and for the lab only.
"""
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Mock Shop API", version="1.0")

USERS = {
    "alice": {"id": 1, "password": "alice123", "email": "alice@example.com"},
    "bob":   {"id": 2, "password": "bob123",   "email": "bob@example.com"},
    "carol": {"id": 3, "password": "carol123", "email": "carol@example.com"},
}
TOKENS = {f"token-{name}": name for name in USERS}   # token-alice -> alice

ORDERS = {
    101: {"id": 101, "owner_id": 1, "item": "Laptop",     "amount": 55000, "card_last4": "4242"},
    102: {"id": 102, "owner_id": 1, "item": "Mouse",      "amount": 800,   "card_last4": "4242"},
    201: {"id": 201, "owner_id": 2, "item": "Phone",      "amount": 30000, "card_last4": "1111"},
    202: {"id": 202, "owner_id": 2, "item": "Earbuds",    "amount": 2500,  "card_last4": "1111"},
    301: {"id": 301, "owner_id": 3, "item": "Monitor",    "amount": 15000, "card_last4": "9999"},
}


class Login(BaseModel):
    username: str
    password: str


def current_user(authorization: str | None):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    name = TOKENS.get(authorization.split(" ", 1)[1])
    if not name:
        raise HTTPException(status_code=401, detail="Invalid token")
    return name, USERS[name]


# ---------- DOCUMENTED endpoints (listed in openapi/openapi.yaml) ----------
@app.post("/api/v1/login")
def login(body: Login):
    u = USERS.get(body.username)
    if not u or u["password"] != body.password:
        raise HTTPException(status_code=401, detail="Bad credentials")
    return {"token": f"token-{body.username}"}


@app.get("/api/v1/users/me")
def me(authorization: str | None = Header(default=None)):
    name, u = current_user(authorization)
    return {"username": name, "id": u["id"], "email": u["email"]}


@app.get("/api/v1/orders")
def my_orders(authorization: str | None = Header(default=None)):
    _, u = current_user(authorization)
    return [o for o in ORDERS.values() if o["owner_id"] == u["id"]]


@app.get("/api/v1/orders/{order_id}")
def get_order(order_id: int, authorization: str | None = Header(default=None)):
    current_user(authorization)          # logged in? yes.
    order = ORDERS.get(order_id)         # BUG (BOLA): owner is never checked!
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return order


# ---------- UNDOCUMENTED endpoints (shadow / zombie) ----------
@app.get("/api/v1/admin/export")
def admin_export(authorization: str | None = Header(default=None)):
    current_user(authorization)
    return {"orders": list(ORDERS.values())}


@app.get("/api/v0/users")
def old_users():
    return [{"id": u["id"], "email": u["email"]} for u in USERS.values()]
