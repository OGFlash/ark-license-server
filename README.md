# ARK Watchdog — License Server

FastAPI service that issues RS256-signed JWTs to licensed clients of ARK Watchdog.

## What this repo does
- Validates license keys and machine seats via `POST /api/activate`
- Issues short-lived signed JWTs for valid activations
- Stores key data in `valid_keys.json`
- Lets admins create/update keys via `POST /admin/upsert`

## Main files
- `license_server.py` — API + activation + admin endpoints
- `valid_keys.json` — local key store (JSON)
- `gen_keys.py` — generates `private.pem` and `public.pem`
- `customer-add.py` — CLI to add/update a user key with a specific time period

## License record shape
Each key is stored like this:

```json
{
  "active": true,
  "plan": "monthly",
  "expires_unix": 1767225600,
  "seats": 1,
  "machines": [],
  "user_id": "cust_123",
  "user_name": "Jane Doe",
  "user_email": "jane@example.com"
}
```

`user_id`, `user_name`, and `user_email` are optional metadata used to track who the key belongs to.

## Add a new key for a specific user + time period
Use the provisioning script:

```bash
python customer-add.py \
  --user-name "Jane Doe" \
  --user-email "jane@example.com" \
  --months 3 \
  --plan "quarterly" \
  --seats 1 \
  --admin-token "<YOUR_ADMIN_TOKEN>" \
  --api-base "https://api.license-arkwatchdog.com"
```

Notes:
- Duration can be combined using `--days`, `--months`, `--years`.
- If you omit `--key`, a key is auto-generated from the user name.
- To update an existing key, pass `--key YOUR-KEY-HERE`.
- For local/offline updates (no running API), add `--store-file valid_keys.json`.
- You can also set env vars instead of flags:
  - `LW_ADMIN_TOKEN`
  - `LW_API_BASE`

## Admin key dashboard (UI)
Open this page in your browser:

- `https://api.license-arkwatchdog.com/admin/dashboard` (Render)
- `http://localhost:8000/admin/dashboard` (local)

What it provides:
- Token-protected key list with status values: `active`, `inactive`, `expired`, `at_capacity`
- Seat usage columns (`seats`, `used`, `remaining`)
- Quick create/update form for new paid customers

How to use:
1. Paste your admin token in the top field.
2. Click **Load Dashboard** to fetch all keys.
3. Fill the form and click **Save Key** to create/update a license.

## Run locally
1. Install deps:
   ```bash
   pip install -r requirements.txt
   ```
2. Generate signing keys (once):
   ```bash
   python gen_keys.py
   ```
3. Start server:
   ```bash
   uvicorn license_server:app --reload --host 0.0.0.0 --port 8000
   ```
4. Health check:
   - `GET http://localhost:8000/health`

## Environment variables
- `APP_ID` (default: `ark-watchdog`)
- `LICENSE_KEYS_FILE` (default: `./valid_keys.json`)
- `TOKEN_TTL_SECONDS` (default: `86400`)
- `TOKEN_CLOCK_SKEW_SECONDS` (default: `120`) - backdates `iat`/`nbf` to tolerate client clock drift
- `ADMIN_TOKEN` (required for admin endpoints)
- `LW_PRIVATE_KEY_PEM` or `LW_PRIVATE_KEY_FILE`

## Troubleshooting activation
- Error: `token decode failed: The token is not yet valid (iat)`
   - Cause: client machine clock is behind server time.
   - Fixes:
      1. Ensure client system date/time is correct (auto-sync enabled).
      2. Set `TOKEN_CLOCK_SKEW_SECONDS=120` (or increase to `300` for larger drift) on server.
      3. Redeploy the server after changing env vars.
