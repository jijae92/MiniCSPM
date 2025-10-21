from datetime import datetime, timezone

import pytest

from models import Finding, ExecutionResult, Score, Summary


def test_finding_validates_status_and_severity():
    finding = Finding(
        id="CIS-0",
        title="Sample",
        cis="0.0",
        service="iam",
        severity="HIGH",
        status="PASS",
        checked_at=datetime.now(timezone.utc),
    )
    assert finding.status == "PASS"


def test_finding_rejects_invalid_severity():
    with pytest.raises(ValueError):
        Finding(
            id="CIS-0",
            title="Bad",
            cis="0.0",
            service="iam",
            severity="CRITICAL",
            status="PASS",
            checked_at=datetime.now(timezone.utc),
        )


def test_execution_result_serializes():
    result = ExecutionResult(
        account_id="123456789012",
        region="us-east-1",
        timestamp=datetime.now(timezone.utc),
        findings=[],
        score=Score(total=0, passed=0, failed=0, weighted=100),
        summary=Summary(),
    )
    payload = result.to_dict()
    assert payload["account_id"] == "123456789012"
