"""Allowlist utilities for waiving MiniCSPM findings."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from models import Finding

ISO_FORMATS = ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%z")


@dataclass
class AllowlistEntry:
    control_id: str
    resource_id: str
    reason: str
    owner: str
    created_at: datetime
    expires_at: datetime

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> Optional["AllowlistEntry"]:
        try:
            created = _parse_datetime(data.get("createdAt"))
            expires = _parse_datetime(data.get("expiresAt"))
            if not created or not expires:
                return None
            return cls(
                control_id=str(data.get("control_id", "")).upper(),
                resource_id=str(data.get("resource_id", "")),
                reason=str(data.get("reason", "")),
                owner=str(data.get("owner", "")),
                created_at=created,
                expires_at=expires,
            )
        except Exception:
            return None

    def matches(self, finding: Finding) -> bool:
        if not self.control_id or self.control_id != finding.id.upper():
            return False
        if self.resource_id in ("*", ""):
            return True
        resources = finding.resource_ids or []
        return any(r == self.resource_id for r in resources)

    def is_expired(self, reference: Optional[datetime] = None) -> bool:
        reference = reference or datetime.now(timezone.utc)
        return self.expires_at < reference

    def to_dict(self) -> Dict[str, str]:
        return {
            "control_id": self.control_id,
            "resource_id": self.resource_id,
            "reason": self.reason,
            "owner": self.owner,
            "createdAt": self.created_at.isoformat(),
            "expiresAt": self.expires_at.isoformat(),
        }


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        pass
    for fmt in ISO_FORMATS:
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


class Allowlist:
    def __init__(self, entries: Iterable[AllowlistEntry]):
        self._entries = list(entries)

    @property
    def entries(self) -> List[AllowlistEntry]:
        return list(self._entries)

    def match(self, finding: Finding, reference: Optional[datetime] = None) -> Optional[AllowlistEntry]:
        for entry in self._entries:
            if entry.is_expired(reference):
                continue
            if entry.matches(finding):
                return entry
        return None

    def expired(self, reference: Optional[datetime] = None) -> List[AllowlistEntry]:
        reference = reference or datetime.now(timezone.utc)
        return [entry for entry in self._entries if entry.is_expired(reference)]


def load_allowlist(path: Optional[str] = None) -> Allowlist:
    file_path = Path(path or ".minicspm-allow.json")
    if not file_path.exists():
        return Allowlist([])
    try:
        raw = json.loads(file_path.read_text())
    except json.JSONDecodeError:
        return Allowlist([])
    entries = []
    for item in raw:
        entry = AllowlistEntry.from_dict(item)
        if entry:
            entries.append(entry)
    return Allowlist(entries)
