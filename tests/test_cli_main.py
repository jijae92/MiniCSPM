from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from cli import main as cli_main
from cli.main import EXIT_FAILURE, EXIT_SUCCESS
from models import ExecutionResult, Finding, Score, Summary
from settings import Settings


def _sample_result(account_id: str = "123456789012") -> ExecutionResult:
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


def test_scan_writes_json(tmp_path, monkeypatch):
    result = _sample_result()
    captured = {}

    class _EngineStub:
        last_settings = None

        def __init__(self, settings):
            self.settings = settings
            _EngineStub.last_settings = settings

        def run_all_checks(self, context, clients=None, includes=None):
            captured["includes"] = includes
            return result

    def fake_build_local_settings(auto_remediate=None, cis_version=None):
        settings = _settings()
        if cis_version:
            settings.cis_version = cis_version
        return settings

    monkeypatch.setattr(cli_main, "build_local_settings", fake_build_local_settings)
    monkeypatch.setattr(cli_main, "Engine", _EngineStub)

    out_path = tmp_path / "report.json"
    exit_code = cli_main.main(
        [
            "scan",
            "--format",
            "json",
            "--out",
            str(out_path),
            "--includes",
            "CIS-1.1,CIS-4.1",
            "--cis",
            "v5_0",
        ]
    )

    assert exit_code == EXIT_SUCCESS
    payload = json.loads(out_path.read_text())
    assert payload["findings"][0]["id"] == "CIS-1.1"
    assert captured["includes"] == ["CIS-1.1", "CIS-4.1"]
    assert _EngineStub.last_settings.cis_version == "v5_0"


def test_score_command_prints_summary(tmp_path, capsys):
    result = _sample_result()
    result_path = tmp_path / "exec.json"
    result_path.write_text(json.dumps(result.to_dict()))

    exit_code = cli_main.main(["score", "--from", str(result_path)])

    assert exit_code == EXIT_SUCCESS
    captured = capsys.readouterr()
    assert "Mini-CSPM Score Summary" in captured.out
    assert "Weighted Score" in captured.out


def test_findings_command_filters_failures(tmp_path, capsys):
    result = _sample_result()
    passing = result.findings[0].to_dict()
    passing["status"] = "PASS"
    payload = result.to_dict()
    payload["findings"].append(passing)

    result_path = tmp_path / "exec.json"
    result_path.write_text(json.dumps(payload))

    exit_code = cli_main.main(["findings", "--from", str(result_path)])

    assert exit_code == EXIT_SUCCESS
    captured = capsys.readouterr()
    assert "Root account MFA enabled" in captured.out
    assert "PASS" not in captured.out


def test_error_exit_on_failure(monkeypatch):
    def _raise(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(cli_main, "run_scan", _raise)
    exit_code = cli_main.main(["scan"])
    assert exit_code == EXIT_FAILURE
