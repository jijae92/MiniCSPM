from datetime import datetime, timezone

import handler
from engine import ExecutionContext
from models import ExecutionResult, Finding, Score, Summary
from settings import Settings


class _FakeEngine:
    def __init__(self, settings):
        self.settings = settings
        self.persisted = None
        self.published = None

    def run_all_checks(self, context: ExecutionContext, clients=None, includes=None):
        assert clients == {}  # patched in tests
        return _build_result(context.account_id)

    def persist_result(self, result):
        self.persisted = result

    def publish_reports(self, result):
        self.published = result
        return {"csv": {"bucket": "reports", "key": "k.csv", "url": "https://example.com/k.csv"}}

    def export_security_findings(self, result):
        self.exported = result


def _build_result(account_id: str) -> ExecutionResult:
    timestamp = datetime(2024, 1, 1, 0, 0, tzinfo=timezone.utc)
    finding = Finding(
        id="CIS-1.1",
        title="Root account MFA enabled",
        cis="1.1",
        service="iam",
        severity="HIGH",
        status="FAIL",
        resource_ids=[account_id],
        evidence={},
        remediable=False,
        remediation_action="",
        references=[],
        checked_at=timestamp,
    )
    score = Score(total=1, passed=0, failed=1, warned=0, weighted=0)
    summary = Summary(HIGH=1, FAIL=1)
    return ExecutionResult(
        account_id=account_id,
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
        account_id="123456789012",
        aws_region="us-east-1",
    )


def test_lambda_handler_success(monkeypatch):
    settings = _settings()
    fake_engine = _FakeEngine(settings)
    monkeypatch.setattr(handler, "load_settings", lambda: settings)
    monkeypatch.setattr(handler, "Engine", lambda settings: fake_engine)
    monkeypatch.setattr(handler, "_build_clients", lambda settings: {})
    response = handler.lambda_handler({}, {})

    assert response["statusCode"] == 200
    body = response["body"]
    assert body["account_id"] == "123456789012"
    assert body["summary"]["fail"] == 1
    assert body["reports"]["csv"]["url"].startswith("https://example.com")


def test_lambda_handler_failure(monkeypatch):
    settings = _settings()

    class _ExplodingEngine:
        def __init__(self, settings):
            pass

        def run_all_checks(self, *args, **kwargs):
            raise RuntimeError("boom")

    monkeypatch.setattr(handler, "load_settings", lambda: settings)
    monkeypatch.setattr(handler, "Engine", _ExplodingEngine)
    monkeypatch.setattr(handler, "_build_clients", lambda settings: {})

    response = handler.lambda_handler({}, {})
    assert response["statusCode"] == 500
    assert "boom" in response["body"]["error"]
