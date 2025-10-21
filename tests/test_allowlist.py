from datetime import datetime, timezone, timedelta
from pathlib import Path

from allowlist import load_allowlist, Allowlist
from engine import Engine
from models import ExecutionResult, Finding, Score, Summary
from settings import Settings


def _write_allowlist(tmp_path: Path, expires_delta: timedelta) -> Path:
    data = [
        {
            "control_id": "CIS-1.1",
            "resource_id": "123456789012",
            "reason": "pending remediation",
            "owner": "security-team",
            "createdAt": datetime.now(timezone.utc).isoformat(),
            "expiresAt": (datetime.now(timezone.utc) + expires_delta).isoformat(),
        }
    ]
    allow_path = tmp_path / ".minicspm-allow.json"
    allow_path.write_text(__import__("json").dumps(data))
    return allow_path


def test_allowlist_match(tmp_path):
    allow_path = _write_allowlist(tmp_path, timedelta(days=7))
    allowlist = load_allowlist(str(allow_path))
    class DummyFinding:
        id = "CIS-1.1"
        resource_ids = ["123456789012"]
    matched = allowlist.match(DummyFinding())
    assert matched is not None
    assert not allowlist.expired(datetime.now(timezone.utc))


def test_allowlist_expired(tmp_path):
    allow_path = _write_allowlist(tmp_path, timedelta(days=-1))
    allowlist = load_allowlist(str(allow_path))
    class DummyFinding:
        id = "CIS-1.1"
        resource_ids = ["123456789012"]
    assert allowlist.match(DummyFinding()) is None
    assert allowlist.expired(datetime.now(timezone.utc))


def test_engine_applies_allowlist(tmp_path, monkeypatch):
    allow_path = _write_allowlist(tmp_path, timedelta(days=7))

    settings = Settings(
        table_name="MiniCspmResults",
        report_bucket="mini-cspm-local",
        account_id="123456789012",
        aws_region="us-east-1",
    )

    def fake_load_allowlist(path=None):
        return load_allowlist(str(allow_path))

    monkeypatch.setattr("engine.load_allowlist", fake_load_allowlist)
    engine = Engine(settings=settings)
    finding = Finding(
        id="CIS-1.1",
        title="Root account MFA enabled",
        cis="1.1",
        service="iam",
        severity="HIGH",
        status="FAIL",
        resource_ids=["123456789012"],
        evidence={},
        checked_at=datetime.now(timezone.utc),
    )
    result = ExecutionResult(
        account_id="123456789012",
        region="us-east-1",
        timestamp=datetime.now(timezone.utc),
        findings=[finding],
        score=Score(total=1, passed=0, failed=1, warned=0, weighted=0),
        summary=Summary(),
    )
    engine._apply_allowances(result.findings)  # pylint: disable=protected-access
    assert finding.waived is True
    assert engine._summarize(result.findings).WAIVED == 1
