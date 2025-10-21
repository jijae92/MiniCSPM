from datetime import datetime, timezone

from models import ExecutionResult, Finding, Score, Summary
from settings import Settings

import html_report


def _result_with_failures() -> ExecutionResult:
    timestamp = datetime(2024, 1, 1, 0, 0, tzinfo=timezone.utc)
    findings = [
        Finding(
            id="CIS-1.1",
            title="Root account MFA enabled",
            cis="1.1",
            service="iam",
            severity="HIGH",
            status="FAIL",
            resource_ids=["123456789012"],
            evidence={
                "remediations": [
                    {
                        "action": "enable_account_pab",
                        "mode": "APPLY",
                        "applied": True,
                        "message": "Enabled account-level S3 block public access",
                    }
                ]
            },
            remediable=True,
            remediation_action="enable_account_pab",
            references=[],
            checked_at=timestamp,
        ),
        Finding(
            id="CIS-1.2",
            title="No root access keys",
            cis="1.2",
            service="iam",
            severity="MEDIUM",
            status="PASS",
            resource_ids=["123456789012"],
            evidence={},
            remediable=False,
            remediation_action="",
            references=[],
            checked_at=timestamp,
        ),
    ]
    score = Score(total=2, passed=1, failed=1, warned=0, weighted=50)
    summary = Summary(HIGH=1, MEDIUM=0, LOW=0, PASS=1, FAIL=1, WARN=0)
    return ExecutionResult(
        account_id="123456789012",
        region="us-east-1",
        timestamp=timestamp,
        findings=findings,
        score=score,
        summary=summary,
    )


def _settings() -> Settings:
    return Settings(
        table_name="MiniCspmResults",
        report_bucket="mini-cspm-local",
        enable_html=True,
        enable_pdf=False,
        csv_prefix="reports/",
        html_prefix="reports/html/",
        pdf_prefix="reports/pdf/",
        fail_on="HIGH",
        aws_region="us-east-1",
    )


def test_render_html_contains_top_failures_and_remediation():
    html_body = html_report.render_html(_result_with_failures(), _settings())
    assert "Top Failing Controls" in html_body
    assert "Root account MFA enabled" in html_body
    assert "Auto Remediation Summary" in html_body
    assert "enable_account_pab" in html_body


def test_write_html_uploads_to_s3(monkeypatch):
    captured = {}

    def fake_put_object(*, key, body, content_type):
        captured["key"] = key
        captured["body"] = body
        captured["content_type"] = content_type
        return key

    monkeypatch.setattr("html_report.s3io.put_object", fake_put_object)
    monkeypatch.setattr(
        "html_report.s3io.build_report_key",
        lambda prefix, result, ext: "reports/html/123456789012/report.html",
    )

    key = html_report.write_html(_result_with_failures(), _settings())

    assert key == "reports/html/123456789012/report.html"
    assert captured["content_type"] == "text/html"
    assert captured["body"].startswith(b"<!doctype html>")
