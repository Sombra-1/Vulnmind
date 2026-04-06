"""
license.py — Freemium gate and Pro license validation.

Two responsibilities:
  1. Validate a license key (HMAC-SHA256, offline, no network call)
  2. Partition findings into (free, locked) based on tier

Why offline validation?
  - Works in air-gapped environments (common in professional pentesting)
  - No single point of failure (license server going down = tool stops working)
  - Instant validation, no network latency

How HMAC keys work:
  A key is: base64url(payload) + "." + base64url(HMAC-SHA256(SECRET, payload))
  Where payload is JSON: {"tier": "pro", "issued": "2024-01-01"}

  Anyone can decode the payload (it's just base64) — but they can't create
  a valid signature without knowing SECRET. That's the guarantee HMAC provides.

  Honest caveat: SECRET is embedded in this file. A determined attacker who
  decompiles the .pyc file can find it and generate their own keys. This is
  the inherent tradeoff of any offline key system. It stops casual sharing,
  not determined crackers.

Freemium gate logic:
  Free tier:  show 1 finding fully (the highest priority one as a teaser)
              show remaining findings as a dim locked table
  Pro tier:   show all findings fully
"""

import base64
import hashlib
import hmac
import json
from typing import Optional

from vulnmind.config import Config
from vulnmind.parsers.base import Finding

# --- The HMAC secret ---
# This is embedded in the binary. Change it for each major product version.
# To generate a new key, use tools/generate_key.py (not included in the package).
_SECRET = b"vulnmind-pro-v1-2026"

# Priority order for sorting (higher index = lower priority)
_PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, None: 4, "unrated": 4}


# ---------------------------------------------------------------------------
# Key validation
# ---------------------------------------------------------------------------

def validate_key(license_key: str) -> bool:
    """
    Validate a Pro license key.

    Returns True if the key has a valid HMAC signature.
    Returns False for any invalid input — never raises.

    Why use hmac.compare_digest() instead of ==?
      Python's == operator returns early as soon as it finds a mismatch.
      This creates a "timing attack" vulnerability: an attacker can measure
      how long comparisons take to guess the key byte-by-byte.
      hmac.compare_digest() always takes the same time regardless of where
      the mismatch is, preventing timing attacks.
    """
    try:
        if "." not in license_key:
            return False

        payload_b64, sig_b64 = license_key.rsplit(".", 1)

        # Decode both parts
        payload_bytes = base64.urlsafe_b64decode(_pad_b64(payload_b64))
        provided_sig = base64.urlsafe_b64decode(_pad_b64(sig_b64))

        # Recompute the expected signature
        expected_sig = hmac.new(_SECRET, payload_bytes, hashlib.sha256).digest()

        # Constant-time comparison
        return hmac.compare_digest(provided_sig, expected_sig)

    except Exception:
        # Any decoding error, wrong padding, etc. — invalid key
        return False


def get_key_payload(license_key: str) -> Optional[dict]:
    """
    Decode the payload from a valid license key.

    Returns the payload dict if valid, None if invalid.
    Always validate the key first — this trusts the payload after validation.
    """
    if not validate_key(license_key):
        return None
    try:
        payload_b64 = license_key.rsplit(".", 1)[0]
        payload_bytes = base64.urlsafe_b64decode(_pad_b64(payload_b64))
        return json.loads(payload_bytes)
    except Exception:
        return None


def _pad_b64(s: str) -> str:
    """Add base64 padding characters if needed."""
    return s + "=" * (-len(s) % 4)


# ---------------------------------------------------------------------------
# Tier detection
# ---------------------------------------------------------------------------

def get_tier(cfg: Config) -> str:
    """
    Determine the user's tier: 'pro' or 'free'.

    Checks the license key stored in config. Returns 'pro' if the key is
    valid and contains tier='pro', otherwise returns 'free'.
    """
    license_key = cfg.license_key
    if not license_key:
        return "free"

    payload = get_key_payload(license_key)
    if payload and payload.get("tier") == "pro":
        return "pro"

    return "free"


# ---------------------------------------------------------------------------
# Freemium partition
# ---------------------------------------------------------------------------

def partition_findings(findings: list, tier: str) -> tuple:
    """
    Split findings into (free_findings, locked_findings).

    Args:
        findings: All Finding objects from parsers
        tier: 'pro' or 'free'

    Returns:
        (free_findings, locked_findings) — both are lists.
        Pro tier: all findings are free, locked is empty.
        Free tier: the single highest-priority finding is free, rest are locked.

    Why put the highest-priority finding in free?
      It's the most impressive finding in the scan — the one most likely to make
      the user think "I need full analysis of all of these." It's a better teaser
      than showing the first alphabetical or lowest-severity finding.
    """
    if tier == "pro":
        return list(findings), []

    if not findings:
        return [], []

    # Sort by priority: critical first, then high, medium, low, unrated
    sorted_findings = sorted(
        findings,
        key=lambda f: _PRIORITY_ORDER.get(f.priority, 4)
    )

    # Free tier: first finding fully shown, rest locked
    return [sorted_findings[0]], sorted_findings[1:]
