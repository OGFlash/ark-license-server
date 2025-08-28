"""
Minimal license server for ARK Watchdog.

Endpoints:
  - POST /api/activate  {key:str, machine:str, app:str} -> {token:str, expires:int}
  - GET  /health        -> {ok: true, app: "...", keys:int}

Storage:
  - License keys are read from a JSON file (default: valid_keys.json next to this file).
    You can override with env LICENSE_KEYS_FILE="D:\\path\\valid_keys.json".

Key format (JSON):
{
  "ABCDEF-123456": {
    "active": true,
    "plan": "monthly",
    "expires_unix": 1956528000,
    "seats": 1,
    "machines": []       # bound machines (server fills on first activation)
  }
}

Private key:
  - Put a PEM at the same folder as license_server.py named private.pem
    OR set LW_PRIVATE_KEY_FILE to the path
    OR set LW_PRIVATE_KEY_PEM to the PEM text.

token TTL:
  - Default 24h; override with env TOKEN_TTL_SECONDS.
"""

import os
import time
import json
from typing import Dict, Any, List

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field
import jwt  # PyJWT

APP_ID = "ark-watchdog"

# ────────────────────────────────────────────────────────────────────────────────
# Private key loader (env PEM -> env FILE -> ./private.pem)
# ────────────────────────────────────────────────────────────────────────────────

def _load_private_key() -> bytes:
    env_pem = os.environ.get("LW_PRIVATE_KEY_PEM", "")
    env_file = os.environ.get("LW_PRIVATE_KEY_FILE", "")
    if env_pem.strip():
        return env_pem.encode("utf-8")
    if env_file.strip() and os.path.exists(env_file):
        with open(env_file, "rb") as f:
            return f.read()
    default_path = os.path.join(os.path.dirname(__file__), "private.pem")
    if os.path.exists(default_path):
        with open(default_path, "rb") as f:
            return f.read()
    raise RuntimeError(
        "Private key not found. Set LW_PRIVATE_KEY_PEM (PEM text), or LW_PRIVATE_KEY_FILE (path), "
        "or place private.pem next to license_server.py."
    )

PRIVATE_KEY_PEM: bytes = _load_private_key()

# ────────────────────────────────────────────────────────────────────────────────
# License storage (JSON file)
# ────────────────────────────────────────────────────────────────────────────────

_KEYS_PATH = os.environ.get(
    "LICENSE_KEYS_FILE",
    os.path.join(os.path.dirname(__file__), "valid_keys.json"),
)

def _load_keys() -> Dict[str, Dict[str, Any]]:
    if not os.path.exists(_KEYS_PATH):
        # start with empty keys file
        with open(_KEYS_PATH, "w", encoding="utf-8") as f:
            json.dump({}, f, indent=2)
        return {}
    try:
        with open(_KEYS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
        # normalize structure
        for k, v in list(data.items()):
            v.setdefault("active", False)
            v.setdefault("plan", "monthly")
            v.setdefault("expires_unix", 0)
            v.setdefault("seats", 1)
            v.setdefault("machines", [])
        return data
    except Exception as e:
        raise RuntimeError(f"Failed to read keys JSON '{_KEYS_PATH}': {e}")

def _save_keys(keys: Dict[str, Dict[str, Any]]) -> None:
    with open(_KEYS_PATH, "w", encoding="utf-8") as f:
        json.dump(keys, f, indent=2)

LICENSE_KEYS: Dict[str, Dict[str, Any]] = _load_keys()

# ────────────────────────────────────────────────────────────────────────────────
# FastAPI app & models
# ────────────────────────────────────────────────────────────────────────────────

app = FastAPI()

class ActivateReq(BaseModel):
    key: str = Field(..., min_length=3, max_length=128)
    machine: str = Field(..., min_length=6, max_length=256)
    app: str = Field(..., min_length=3, max_length=64)

# Token lifetime (seconds). Default 24h.
TOKEN_TTL_SECONDS = int(os.environ.get("TOKEN_TTL_SECONDS", "86400"))

# ────────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────────

def _now() -> int:
    return int(time.time())

def _issue_token(license_meta: Dict[str, Any], machine: str) -> Dict[str, Any]:
    now = _now()
    exp = now + TOKEN_TTL_SECONDS
    payload: Dict[str, Any] = {
        "aud": APP_ID,
        "sub": APP_ID,
        "machine": machine,
        "plan": license_meta.get("plan", "monthly"),
        "iat": now,
        "nbf": now,
        "exp": exp,
    }
    token = jwt.encode(payload, PRIVATE_KEY_PEM, algorithm="RS256")
    return {"token": token, "expires": exp}

# ────────────────────────────────────────────────────────────────────────────────
# Routes
# ────────────────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"ok": True, "app": APP_ID, "keys": len(LICENSE_KEYS), "store": _KEYS_PATH}

@app.post("/api/activate")
def activate(req: ActivateReq):
    if req.app != APP_ID:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="app mismatch")

    key = req.key.strip()
    meta = LICENSE_KEYS.get(key)
    if not meta or not meta.get("active", False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid key")

    # Subscription expiry
    now = _now()
    exp_sub = int(meta.get("expires_unix", 0))
    if exp_sub <= now:
        raise HTTPException(status_code=status.HTTP_402_PAYMENT_REQUIRED, detail="expired")

    # Machine binding (simple seat model)
    seats = max(1, int(meta.get("seats", 1)))
    machines: List[str] = list(meta.get("machines", []))

    if req.machine in machines:
        # existing bound machine → OK
        pass
    else:
        if len(machines) < seats:
            machines.append(req.machine)
            meta["machines"] = machines
            LICENSE_KEYS[key] = meta
            try:
                _save_keys(LICENSE_KEYS)
            except Exception:
                # non-fatal: still proceed, but you may want to log
                pass
        else:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="seat limit reached")

    return _issue_token(meta, req.machine)
