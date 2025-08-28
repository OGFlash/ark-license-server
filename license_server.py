import os, json, time, re, tempfile
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import jwt  # PyJWT

app = FastAPI()

# ===== Config =====
APP_ID = "ark-watchdog"
LICENSE_KEYS_FILE = os.environ.get("LICENSE_KEYS_FILE") or os.path.join(os.path.dirname(__file__), "valid_keys.json")
TOKEN_TTL = int(os.environ.get("TOKEN_TTL_SECONDS", "86400"))
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN")  # set this in Render → Environment

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

# ===== Helpers =====
def read_store() -> Dict[str, Any]:
    try:
        with open(LICENSE_KEYS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}

def write_store(data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(LICENSE_KEYS_FILE) or ".", exist_ok=True)
    tmp = LICENSE_KEYS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, LICENSE_KEYS_FILE)

def _norm_machine(m: str) -> str:
    """Canonicalize any incoming machine string to 16-char lowercase hex."""
    m = (m or "").strip().lower()
    if re.fullmatch(r"[0-9a-f]{32,}", m):
        return m[:16]
    only_hex = "".join(ch for ch in m if ch in "0123456789abcdef")
    if len(only_hex) >= 16:
        return only_hex[:16]
    return m[:16]

# ===== Models =====
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

def require_admin(token: Optional[str]):
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="admin token not configured")
    if token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="forbidden")

# ===== API =====
@app.get("/health")
def health():
    store = read_store()
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

    # Normalize existing stored machines and incoming machine
    machines: List[str] = [_norm_machine(x) for x in lic.get("machines", [])]
    nmach = _norm_machine(p.machine)
    if not nmach:
        raise HTTPException(status_code=400, detail="bad machine")

    # De-dup and persist normalization if it changed anything
    normalized_changed = (machines != lic.get("machines", []))
    machines = list(dict.fromkeys(machines))  # de-dup preserving order

    if nmach not in machines:
        if len(machines) >= seats:
            raise HTTPException(status_code=409, detail="seat limit reached")
        machines.append(nmach)
        normalized_changed = True

    if normalized_changed:
        lic["machines"] = machines
        store[p.key] = lic
        write_store(store)

    # Mint token with canonical machine id
    exp = min(now + TOKEN_TTL, exp_unix)
    payload = {
        "sub": p.key,
        "aud": APP_ID,
        "machine": nmach,  # canonical 16-char lowercase hex
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
        "machines": [_norm_machine(m) for m in lic.get("machines", [])],
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
    tgt = _norm_machine(payload.machine)
    lic["machines"] = [m for m in [_norm_machine(x) for x in lic.get("machines", [])] if m != tgt]
    store[payload.key] = lic
    write_store(store)
    return {"ok": True, "machines": lic["machines"]}
