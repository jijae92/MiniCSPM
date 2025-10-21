from datetime import datetime, timezone

from models import ExecutionResult, Finding, Score, Summary
from settings import Settings

import pdf_report


def _result() -> ExecutionResult:
    timestamp = datetime(2024, 1, 1, 0, 0, tzinfo=timezone.utc)
    finding = Finding(
        id="CIS-1.1",
        title="Root account MFA enabled",
        cis="1.1",
        service="iam",
        severity="HIGH",
        status="FAIL",
        resource_ids=["123456789012"],
        evidence={},
        remediable=False,
        remediation_action="",
        references=[],
        checked_at=timestamp,
    )
    score = Score(total=1, passed=0, failed=1, warned=0, weighted=0)
    summary = Summary(HIGH=1, FAIL=1)
    return ExecutionResult(
        account_id="123456789012",
        region="us-east-1",
        timestamp=timestamp,
        findings=[finding],
        score=score,
        summary=summary,
    )


def _settings() -> Settings:
    return Settings(
        table_name="MiniCspmResults",
        report_bucket="mini-cspm-local",
        enable_pdf=True,
        csv_prefix="reports/",
        html_prefix="reports/html/",
        pdf_prefix="reports/pdf/",
        fail_on="HIGH",
        aws_region="us-east-1",
    )


def test_write_pdf_uses_renderer(monkeypatch):
    captured = {}

    def fake_put_object(*, key, body, content_type):
        captured["key"] = key
        captured["body"] = body
        captured["content_type"] = content_type
        return key

    monkeypatch.setattr("pdf_report.s3io.put_object", fake_put_object)
    monkeypatch.setattr(
        "pdf_report.s3io.build_report_key",
        lambda prefix, result, ext: "reports/pdf/123456789012/report.pdf",
    )
    monkeypatch.setattr("pdf_report.render_pdf_bytes", lambda html_body, settings: b"%PDF-test")

    key = pdf_report.write_pdf(_result(), _settings())

    assert key == "reports/pdf/123456789012/report.pdf"
    assert captured["content_type"] == "application/pdf"
    assert captured["body"] == b"%PDF-test"


def test_render_pdf_bytes_returns_none_without_renderer(monkeypatch):
    monkeypatch.setattr("pdf_report.HTML", None)
    monkeypatch.setattr("pdf_report._resolve_binary", lambda candidate: None)
    assert pdf_report.render_pdf_bytes("<html></html>", _settings()) is None
