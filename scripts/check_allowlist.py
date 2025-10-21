#!/usr/bin/env python3
"""Validate allowlist entries for expiration."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_PATH = Path(".minicspm-allow.json")


def main() -> int:
    allowlist_path = DEFAULT_PATH
    if not allowlist_path.exists():
        return 0
    try:
        data = json.loads(allowlist_path.read_text())
    except json.JSONDecodeError as exc:
        print(f"::error::Failed to parse {allowlist_path}: {exc}")
        return 1

    now = datetime.now(timezone.utc)
    expired = []
    for entry in data:
        expires = entry.get("expiresAt")
        if not expires:
            continue
        try:
            expiry = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        except ValueError:
            print(f"::warning::Invalid expiresAt format for control {entry.get('control_id')}: {expires}")
            continue
        if expiry < now:
            expired.append(entry)

    if expired:
        print("::error::Expired allowlist entries detected:")
        for entry in expired:
            print(f"  - {entry.get('control_id')} {entry.get('resource_id')} expired {entry.get('expiresAt')}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
