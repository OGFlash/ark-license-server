import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from secrets import choice

import requests


def _read_store(store_file: str) -> dict:
    try:
        with open(store_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}


def _write_store(store_file: str, data: dict) -> None:
    with open(store_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _generate_key(user_name: str) -> str:
    clean = "".join(ch for ch in user_name.upper() if ch.isalnum())
    prefix = (clean[:6] or "USER").ljust(6, "X")
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    suffix = "".join(choice(alphabet) for _ in range(8))
    return f"{prefix}-{suffix[:4]}-{suffix[4:]}"


def _compute_expiration(days: int = 0, months: int = 0, years: int = 0) -> int:
    total_days = days + (months * 30) + (years * 365)
    if total_days <= 0:
        raise ValueError("Duration must be greater than 0 days.")
    now = datetime.now(timezone.utc)
    return int((now + timedelta(days=total_days)).timestamp())


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create or update a license key for a specific user and time period."
    )
    parser.add_argument("--user-name", required=True, help="User full name")
    parser.add_argument("--user-email", required=True, help="User email address")
    parser.add_argument("--user-id", default="", help="Optional external user/customer ID")
    parser.add_argument("--key", default="", help="Provide existing/new key (auto-generated if omitted)")
    parser.add_argument("--days", type=int, default=0, help="License duration in days")
    parser.add_argument("--months", type=int, default=0, help="License duration in months (30-day months)")
    parser.add_argument("--years", type=int, default=0, help="License duration in years (365-day years)")
    parser.add_argument("--plan", default="monthly", help="Plan label (e.g. monthly, annual, lifetime)")
    parser.add_argument("--seats", type=int, default=1, help="Number of machine seats")
    parser.add_argument(
        "--api-base",
        default=os.environ.get("LW_API_BASE")
        or os.environ.get("API_BASE")
        or "https://api.license-arkwatchdog.com",
        help="License API base URL",
    )
    parser.add_argument(
        "--admin-token",
        default=os.environ.get("LW_ADMIN_TOKEN") or os.environ.get("ADMIN_TOKEN", ""),
        help="Admin token (or set LW_ADMIN_TOKEN env var)",
    )
    parser.add_argument(
        "--store-file",
        default="",
        help="Optional local JSON store path (e.g. valid_keys.json) to upsert directly without API",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    try:
        expires_unix = _compute_expiration(args.days, args.months, args.years)
    except ValueError as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)

    license_key = args.key or _generate_key(args.user_name)
    api_base = args.api_base.rstrip("/")

    payload = {
        "key": license_key,
        "active": True,
        "plan": args.plan,
        "expires_unix": expires_unix,
        "seats": int(args.seats),
        "user_id": args.user_id or None,
        "user_name": args.user_name,
        "user_email": args.user_email,
    }

    if args.store_file:
        store = _read_store(args.store_file)
        current = store.get(license_key, {})
        store[license_key] = {
            "active": True,
            "plan": args.plan,
            "expires_unix": expires_unix,
            "seats": int(args.seats),
            "machines": current.get("machines", []),
            "user_id": args.user_id or None,
            "user_name": args.user_name,
            "user_email": args.user_email,
        }
        _write_store(args.store_file, store)
        print(f"Local upsert complete: {args.store_file}")
    else:
        if not args.admin_token:
            print("ERROR: Missing admin token. Pass --admin-token or set LW_ADMIN_TOKEN.")
            sys.exit(1)

        url = f"{api_base}/admin/upsert"
        headers = {
            "X-Admin-Token": args.admin_token,
            "Content-Type": "application/json",
        }

        try:
            response = requests.post(url, headers=headers, json=payload, timeout=20)
        except requests.RequestException as exc:
            print(f"Request failed: {exc}")
            sys.exit(2)

        print(f"Status: {response.status_code}")
        try:
            print("Response:")
            print(json.dumps(response.json(), indent=2))
        except ValueError:
            print("Response text:", response.text)

    expires_iso = datetime.fromtimestamp(expires_unix, tz=timezone.utc).isoformat()
    print(f"\nCreated/updated key: {license_key}")
    print(f"User: {args.user_name} <{args.user_email}>")
    print(f"Expires (UTC): {expires_iso}")


if __name__ == "__main__":
    main()