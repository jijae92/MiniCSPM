from datetime import datetime, timezone

from asff import finding_to_asff
from engine import Engine
from models import ExecutionResult, Finding, Score, Summary
from settings import Settings


def _sample_finding(status: str = "FAIL") -> Finding:
    return Finding(
        id="CIS-1.1",
        title="Root account MFA enabled",
        cis="1.1",
        service="iam",
        severity="HIGH",
        status=status,
        resource_ids=["123456789012"],
        evidence={"mfa_enabled": False},
        remediable=False,
        remediation_action="Enable MFA for root user",
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"],
        checked_at=datetime(2025, 1, 1, 0, 0, tzinfo=timezone.utc),
    )


def test_finding_to_asff_structure():
    product_arn = "arn:aws:securityhub:us-east-1:111122223333:product/111122223333/default"
    finding = _sample_finding()
    asff = finding_to_asff(finding, "123456789012", "us-east-1", product_arn, "v5_0")

    assert asff["ProductArn"] == product_arn
    assert asff["AwsAccountId"] == "123456789012"
    assert asff["Severity"]["Label"] == "HIGH"
    assert asff["Compliance"]["RelatedRequirements"] == ["CIS-AWS-1.1(v5.0)"]
    assert asff["Resources"][0]["Type"] == "AwsAccount"
    assert asff["RecordState"] == "ACTIVE"


def test_engine_exports_to_security_hub(monkeypatch):
    product_arn = "arn:aws:securityhub:us-east-1:111122223333:product/111122223333/default"
    settings = Settings(
        table_name="MiniCspmResults",
        report_bucket="mini-cspm-local",
        export_to_security_hub=True,
        product_arn=product_arn,
        cis_version="v1_5",
        account_id="111122223333",
        aws_region="us-east-1",
    )

    stub = _SecurityHubStub()
    engine = Engine(settings=settings, securityhub_client=stub)
    result = ExecutionResult(
        account_id="111122223333",
        region="us-east-1",
        timestamp=datetime.now(timezone.utc),
        findings=[_sample_finding(), _sample_finding(status="PASS")],
        score=Score(total=2, passed=1, failed=1, warned=0, weighted=50),
        summary=Summary(HIGH=1, FAIL=1, PASS=1),
    )

    engine.export_security_findings(result)

    assert len(stub.calls) == 1
    findings = stub.calls[0]
    assert len(findings) == 1
    assert findings[0]["Compliance"]["Status"] == "FAILED"


class _SecurityHubStub:
    def __init__(self):
        self.calls = []

    def batch_import_findings(self, Findings):
        self.calls.append(Findings)
        return {"FailedCount": 0, "SuccessCount": len(Findings)}
