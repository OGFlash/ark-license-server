# ARK Watchdog — License Server

FastAPI service that issues **RS256-signed JWTs** to licensed clients of ARK Watchdog.

- Endpoint: `POST /api/activate` → returns a short-lived token bound to the machine
- Health: `GET /health`
- Storage: simple JSON file (`valid_keys.json`) for license keys and machine seats
- Secrets: RSA **private key** (`private.pem`) stays on the server; the client ships the **public key**

> Pair this server with the client’s `license_client.py` (set `API_BASE` to your domain and paste your public key there).

---

## Repo layout

