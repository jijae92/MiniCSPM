"""Shared data models for findings and execution results."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


SEVERITIES = {"LOW", "MEDIUM", "HIGH"}
STATUSES = {"PASS", "FAIL", "WARN"}


def _ensure_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return datetime.fromisoformat(value)
    raise TypeError(f"Unsupported datetime value: {value!r}")


@dataclass
class Finding:
    id: str
    title: str
    cis: str
    service: str
    severity: str
    status: str
    resource_ids: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediable: bool = False
    remediation_action: str = ""
    references: List[str] = field(default_factory=list)
    checked_at: datetime = field(default_factory=datetime.utcnow)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}")
        if self.status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        if isinstance(self.checked_at, str):
            self.checked_at = datetime.fromisoformat(self.checked_at)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        payload = data.copy()
        payload["checked_at"] = _ensure_datetime(payload["checked_at"])
        return cls(**payload)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["checked_at"] = self.checked_at.isoformat()
        return payload


@dataclass
class Score:
    total: int
    passed: int
    failed: int
    weighted: int
    warned: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Summary:
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0
    PASS: int = 0
    FAIL: int = 0
    WARN: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExecutionResult:
    account_id: str
    region: str
    timestamp: datetime
    findings: List[Finding]
    score: Score
    summary: Summary = field(default_factory=Summary)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "account_id": self.account_id,
            "region": self.region,
            "timestamp": self.timestamp.isoformat(),
            "findings": [finding.to_dict() for finding in self.findings],
            "score": self.score.to_dict(),
            "summary": self.summary.to_dict(),
        }


@dataclass
class ExecutionContext:
    account_id: Optional[str]
    region: str
    invoked_at: datetime
    schedule_arn: Optional[str] = None


@dataclass
class RemediationResult:
    action: str
    mode: str
    applied: bool
    message: str
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
