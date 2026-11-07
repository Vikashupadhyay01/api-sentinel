# mock-api
Deliberately vulnerable shop API used as the target for API-Sentinel.

```bash
cd mock-api
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --port 8000
```
Planted issues: BOLA on `/api/v1/orders/{id}`, shadow endpoint `/api/v1/admin/export`,
zombie endpoint `/api/v0/users`. Lab use only - never deploy this.
