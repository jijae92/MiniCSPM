import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path

from engine import Engine
from models import ExecutionResult, Finding, Score, Summary
from settings import Settings


class _FakeS3Client:
    def __init__(self) -> None:
        self.last_put = None

    def put_object(self, *, Bucket: str, Key: str, Body: bytes, ContentType: str) -> None:
        self.last_put = {"Bucket": Bucket, "Key": Key, "Body": Body, "ContentType": ContentType}

    def generate_presigned_url(self, ClientMethod: str, Params: dict, ExpiresIn: int) -> str:
        return f"https://example.com/{Params['Key']}"


def _make_settings() -> Settings:
    return Settings(
        table_name="MiniCspmResults",
        report_bucket="mini-cspm-local",
        enable_pdf=False,
        enable_html=False,
        auto_remediate=0,
        csv_prefix="reports/",
        html_prefix="reports/",
        pdf_prefix="reports/",
        fail_on="HIGH",
        aws_region="us-east-1",
        enable_presigned_urls=True,
        max_check_workers=1,
    )


def _make_result() -> ExecutionResult:
    timestamp = datetime(2024, 1, 1, 0, 0, tzinfo=timezone.utc)
    finding = Finding(
        id="CIS-1.1",
        title="Root account MFA enabled",
        cis="1.1",
        service="iam",
        severity="HIGH",
        status="FAIL",
        resource_ids=["123456789012"],
        evidence={"mfa_enabled": False},
        remediable=False,
        remediation_action="",
        references=[],
        checked_at=timestamp,
    )
    score = Score(total=1, passed=0, failed=1, weighted=0, warned=0)
    summary = Summary(HIGH=1, FAIL=1)
    return ExecutionResult(
        account_id="123456789012",
        region="us-east-1",
        timestamp=timestamp,
        findings=[finding],
        score=score,
        summary=summary,
    )


def test_write_csv_report_matches_contract():
    fake_s3 = _FakeS3Client()
    settings = _make_settings()
    engine = Engine(settings=settings, s3_client=fake_s3)
    result = _make_result()

    key, url = engine._write_csv_report(result)  # pylint: disable=protected-access

    assert key == "reports/123456789012/20240101T000000Z.csv"
    assert url == "https://example.com/reports/123456789012/20240101T000000Z.csv"

    assert fake_s3.last_put is not None
    assert fake_s3.last_put["Bucket"] == "mini-cspm-local"
    assert fake_s3.last_put["Key"] == key
    assert fake_s3.last_put["ContentType"] == "text/csv"

    csv_body = fake_s3.last_put["Body"].decode("utf-8")
    expected = Path("tests/fixtures/expected_csv_report.csv").read_text()
    reader = csv.reader(io.StringIO(csv_body))
    rows = list(reader)
    expected_rows = list(csv.reader(io.StringIO(expected)))
    assert rows == expected_rows

    assert rows[0] == [
        "timestamp",
        "account_id",
        "control_id",
        "title",
        "severity",
        "status",
        "resource_ids",
        "notes",
    ]
    assert rows[1][0] == result.timestamp.isoformat()
    assert rows[1][1] == "123456789012"
    assert rows[1][2] == "CIS-1.1"
    assert json.loads(rows[1][7]) == {"mfa_enabled": False}
