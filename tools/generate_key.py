"""
tools/generate_key.py — Admin tool to generate Pro license keys.

NOT shipped in the pip package. For internal use only.

Usage:
    python tools/generate_key.py
    python tools/generate_key.py --tier pro --note "customer@email.com"

This script must use the same _SECRET as vulnmind/license.py.
If you change the secret in license.py, update it here too.
"""

import argparse
import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone

# Must match the secret in vulnmind/license.py exactly
_SECRET = b"vulnmind-pro-v1-2026"


def generate_key(tier: str = "pro", note: str = "") -> str:
    """Generate a VulnMind Pro license key."""
    payload = {
        "tier": tier,
        "issued": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
    }
    if note:
        payload["note"] = note

    payload_bytes = json.dumps(payload, separators=(",", ":")).encode()
    sig = hmac.new(_SECRET, payload_bytes, hashlib.sha256).digest()

    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode().rstrip("=")
    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")

    return f"{payload_b64}.{sig_b64}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate VulnMind Pro license keys")
    parser.add_argument("--tier", default="pro", choices=["pro"], help="License tier")
    parser.add_argument("--note", default="", help="Optional note (e.g. customer email)")
    args = parser.parse_args()

    key = generate_key(tier=args.tier, note=args.note)
    print(f"\nGenerated {args.tier.upper()} license key:")
    print(f"\n  {key}\n")
    print(f"Customer runs:  vulnmind config set-license {key}")
