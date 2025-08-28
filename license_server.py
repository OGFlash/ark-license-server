import os, json, time, tempfile
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import jwt  # PyJWT

app = FastAPI()

# ----- Config -----
APP_ID = "ark-watchdog"
LICENSE_KEYS_FILE = os.environ.get("LICENSE_KEYS_FILE") or os.path.join(os.path.dirname(__file__), "valid_keys.json")
TOKEN_TTL = int(os.environ.get("TOKEN_TTL_SECONDS", "86400"))
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN")

def _load_private_key() -> str:
    pem = os.environ.get("LW_PRIVATE_KEY_PEM")
    if pem:
        return pem
    key_path = os.environ.get("LW_PRIVATE_KEY_FILE")
    if not key_path:
        here = os.path.dirname(__file__)
        fallback = os.path.join(here, "private.pem")
        if os.path.exists(fallback):
            key_path = fallback
    if key_path and os.path.exists(key_path):
        return open(key_path, "r", encoding="utf-8").read()
    raise RuntimeError("Private key missing: set LW_PRIVATE_KEY_PEM or LW_PRIVATE_KEY_FILE, or place private.pem next to license_server.py")

PRIVATE_KEY_PEM = _load_private_key()

# ----- Store helpers (always read from disk) -----
def read_store() -> Dict[str, Any]:
    try:
        with open(LICENSE_KEYS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        # keep service alive even if file is corrupted
        return {}

def write_store(data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(LICENSE_KEYS_FILE) or ".", exist_ok=True)
    tmp = LICENSE_KEYS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, LICENSE_KEYS_FILE)

# ----- Models -----
class ActivatePayload(BaseModel):
    key: str
    machine: str
    app: str

class UpsertPayload(BaseModel):
    key: str
    active: bool = True
    plan: str = "monthly"
    expires_unix: int
    seats: int = 1

class RemoveMachinePayload(BaseModel):
    key: str
    machine: str

# ----- Admin guard -----
def require_admin(token: Optional[str]):
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="admin token not configured")
    if token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="forbidden")

# ----- API -----
@app.get("/health")
def health():
    store = read_store()  # fresh read every call
    return {"ok": True, "app": APP_ID, "keys": len(store), "store": LICENSE_KEYS_FILE}

@app.post("/api/activate")
def activate(p: ActivatePayload):
    if p.app != APP_ID:
        raise HTTPException(status_code=403, detail="app mismatch")

    store = read_store()
    lic = store.get(p.key)
    if not lic:
        raise HTTPException(status_code=403, detail="invalid key")
    if not lic.get("active", False):
        raise HTTPException(status_code=403, detail="inactive")

    now = int(time.time())
    exp_unix = int(lic.get("expires_unix", 0))
    if exp_unix <= now:
        raise HTTPException(status_code=402, detail="expired")

    seats = int(lic.get("seats", 1))
    machines: List[str] = list(lic.get("machines", []))

    if p.machine not in machines:
        if len(machines) >= seats:
            raise HTTPException(status_code=409, detail="seat limit reached")
        machines.append(p.machine)
        lic["machines"] = machines
        store[p.key] = lic
        write_store(store)  # persist binding

    # mint token
    exp = min(now + TOKEN_TTL, exp_unix)
    payload = {
        "sub": p.key,
        "aud": APP_ID,
        "machine": p.machine,
        "plan": lic.get("plan", "unknown"),
        "iat": now,
        "nbf": now,
        "exp": exp,
    }
    token = jwt.encode(payload, PRIVATE_KEY_PEM, algorithm="RS256")
    return {"token": token, "expires": exp}

# ----- Admin endpoints -----
@app.post("/admin/upsert")
def admin_upsert(payload: UpsertPayload, x_admin_token: str = Header(default="")):
    require_admin(x_admin_token)
    store = read_store()
    lic = store.get(payload.key, {})
    lic.update({
        "active": bool(payload.active),
        "plan": payload.plan,
        "expires_unix": int(payload.expires_unix),
        "seats": int(payload.seats),
        "machines": lic.get("machines", []),
    })
    store[payload.key] = lic
    write_store(store)
    return {"ok": True, "key": payload.key}

@app.post("/admin/remove_machine")
def admin_remove_machine(payload: RemoveMachinePayload, x_admin_token: str = Header(default="")):
    require_admin(x_admin_token)
    store = read_store()
    lic = store.get(payload.key)
    if not lic:
        raise HTTPException(status_code=404, detail="not found")
    lic["machines"] = [m for m in lic.get("machines", []) if m != payload.machine]
    store[payload.key] = lic
    write_store(store)
    return {"ok": True, "machines": lic["machines"]}
