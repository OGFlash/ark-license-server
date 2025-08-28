# license_server.py
import os, json, time, re
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import jwt  # PyJWT

app = FastAPI(title="Ark Watchdog Licensing", version="1.0.0")

# ────────────────────────────────────────────────────────────────────────────────
# Config
# ────────────────────────────────────────────────────────────────────────────────
APP_ID = os.environ.get("APP_ID", "ark-watchdog")
# On Render, set this to /data/valid_keys.json (persistent disk)
LICENSE_KEYS_FILE = os.environ.get("LICENSE_KEYS_FILE") or os.path.join(
    os.path.dirname(__file__), "valid_keys.json"
)
TOKEN_TTL = int(os.environ.get("TOKEN_TTL_SECONDS", "86400"))  # 1 day default
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN")  # set in Render → Environment

# ────────────────────────────────────────────────────────────────────────────────
# Private key loader (supports PEM in env with \n)
# ────────────────────────────────────────────────────────────────────────────────
def _load_private_key() -> str:
    pem = os.environ.get("LW_PRIVATE_KEY_PEM")
    if pem:
        # if provided with literal "\n", convert to real newlines
        if "\\n" in pem and "-----BEGIN" in pem:
            pem = pem.replace("\\n", "\n")
        return pem
    key_path = os.environ.get("LW_PRIVATE_KEY_FILE")
    if not key_path:
        here = os.path.dirname(__file__)
        fallback = os.path.join(here, "private.pem")
        if os.path.exists(fallback):
            key_path = fallback
    if key_path and os.path.exists(key_path):
        with open(key_path, "r", encoding="utf-8") as f:
            return f.read()
    raise RuntimeError(
        "Private key missing: set LW_PRIVATE_KEY_PEM (PEM text) or "
        "LW_PRIVATE_KEY_FILE (path), or place private.pem next to license_server.py"
    )

PRIVATE_KEY_PEM = _load_private_key()

# ────────────────────────────────────────────────────────────────────────────────
# Store helpers
# ────────────────────────────────────────────────────────────────────────────────
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
    # allow 32/64+ hex — then trim
    if re.fullmatch(r"[0-9a-f]{16,}", m):
        return m[:16]
    only_hex = "".join(ch for ch in m if ch in "0123456789abcdef")
    if len(only_hex) >= 16:
        return only_hex[:16]
    return m[:16]

def _require_admin(token: Optional[str]):
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="admin token not configured")
    if token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="forbidden")

# ────────────────────────────────────────────────────────────────────────────────
# Models
# ────────────────────────────────────────────────────────────────────────────────
class ActivatePayload(BaseModel):
    key: str
    app: str = Field(..., description="should match APP_ID on server")
    # accept either of these (client may send one or the other)
    machine: Optional[str] = None
    fingerprint: Optional[str] = None
    version: Optional[int] = None  # ignored; reserved for future use

class UpsertPayload(BaseModel):
    key: str
    active: bool = True
    plan: str = "monthly"
    expires_unix: int
    seats: int = 1

class RemoveMachinePayload(BaseModel):
    key: str
    machine: str

# ────────────────────────────────────────────────────────────────────────────────
# CORS (handy for quick tests; tighten if needed)
# ────────────────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ────────────────────────────────────────────────────────────────────────────────
# API
# ────────────────────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    store = read_store()
    return {"ok": True, "app": APP_ID, "keys": len(store), "store": LICENSE_KEYS_FILE}

@app.post("/api/activate")
def activate(p: ActivatePayload):
    if p.app != APP_ID:
        raise HTTPException(status_code=403, detail="app mismatch")

    machine_in = p.machine or p.fingerprint or ""
    nmach = _norm_machine(machine_in)
    if not nmach:
        raise HTTPException(status_code=422, detail="machine/fingerprint required")

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
    # normalize any existing machines
    machines: List[str] = [_norm_machine(x) for x in lic.get("machines", [])]
    machines = list(dict.fromkeys(machines))  # de-dup preserve order

    if nmach not in machines:
        if len(machines) >= seats:
            raise HTTPException(status_code=409, detail="seat limit reached")
        machines.append(nmach)
        # persist
        lic["machines"] = machines
        store[p.key] = lic
        write_store(store)

    # Mint token (include both 'aud' and 'app' for client compatibility)
    exp = min(now + TOKEN_TTL, exp_unix)
    payload = {
        "sub": p.key,
        "aud": APP_ID,
        "app": APP_ID,
        "machine": nmach,
        "plan": lic.get("plan", "unknown"),
        "iat": now,
        "nbf": now,
        "exp": exp,
    }
    token = jwt.encode(payload, PRIVATE_KEY_PEM, algorithm="RS256")
    return {"token": token, "expires": exp, "claims": payload}

# ── Admin endpoints ─────────────────────────────────────────────────────────────
@app.post("/admin/upsert")
def admin_upsert(payload: UpsertPayload, x_admin_token: str = Header(default="")):
    _require_admin(x_admin_token)
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
    return {"ok": True, "key": payload.key, "machines": lic["machines"]}

@app.post("/admin/remove_machine")
def admin_remove_machine(payload: RemoveMachinePayload, x_admin_token: str = Header(default="")):
    _require_admin(x_admin_token)
    store = read_store()
    lic = store.get(payload.key)
    if not lic:
        raise HTTPException(status_code=404, detail="not found")
    tgt = _norm_machine(payload.machine)
    lic["machines"] = [m for m in [_norm_machine(x) for x in lic.get("machines", [])] if m != tgt]
    store[payload.key] = lic
    write_store(store)
    return {"ok": True, "machines": lic["machines"]}

@app.get("/admin/get/{key}")
def admin_get(key: str, x_admin_token: str = Header(default="")):
    _require_admin(x_admin_token)
    store = read_store()
    lic = store.get(key)
    if not lic:
        raise HTTPException(status_code=404, detail="not found")
    return {"key": key, **lic}

@app.get("/admin/list")
def admin_list(x_admin_token: str = Header(default="")):
    _require_admin(x_admin_token)
    store = read_store()
    return {"count": len(store), "keys": list(store.keys())}
