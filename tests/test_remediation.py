from datetime import datetime, timezone

import pytest

from models import Finding, RemediationResult
from remediation import SAFE_ACTIONS, remediate, register
from settings import Settings


def _base_finding(action: str) -> Finding:
    return Finding(
        id="TEST-1",
        title="Test",
        cis="0.0",
        service="test",
        severity="HIGH",
        status="FAIL",
        resource_ids=["123456789012"],
        evidence={},
        remediable=True,
        remediation_action=action,
        references=[],
        checked_at=datetime.now(timezone.utc),
    )


def _settings(mode: int) -> Settings:
    return Settings(
        table_name="MiniCspmResults",
        report_bucket="mini-cspm-local",
        auto_remediate=mode,
        account_id="123456789012",
        aws_region="us-east-1",
        remediation_apply_env_enabled=True,
        remediation_apply_parameter="/mini-cspm/demo-apply",
    )


class _Clients:
    def __init__(self):
        self.s3 = _S3Client()
        self.iam = _IAMClient()
        self.ec2 = _EC2Client()
        self.logs = _LogsClient()
        self.cloudwatch = _CloudWatchClient()

    def as_dict(self):
        return {
            "s3": self.s3,
            "iam": self.iam,
            "ec2": self.ec2,
            "logs": self.logs,
            "cloudwatch": self.cloudwatch,
        }


class _S3Client:
    def __init__(self):
        self.calls = 0

    def put_public_access_block(self, **kwargs):
        self.calls += 1
        return kwargs


class _IAMClient:
    def __init__(self):
        self.calls = 0

    def update_account_password_policy(self, **kwargs):
        self.calls += 1
        return kwargs


class _EC2Client:
    def __init__(self):
        self.calls = 0

    def revoke_security_group_ingress(self, **kwargs):
        self.calls += 1
        return kwargs


class _LogsClient:
    def __init__(self):
        self.calls = 0

    def put_metric_filter(self, **kwargs):
        self.calls += 1
        return kwargs


class _CloudWatchClient:
    def __init__(self):
        self.calls = 0

    def put_metric_alarm(self, **kwargs):
        self.calls += 1
        return kwargs


@pytest.mark.parametrize("action", list(SAFE_ACTIONS))
def test_remediate_dry_run(action):
    clients = _Clients()
    finding = _base_finding(action)
    result = remediate(action, finding, _settings(1), clients.as_dict())
    assert isinstance(result, RemediationResult)
    assert result.mode == "DRY_RUN"
    assert result.applied is False


def test_remediate_apply_safe_action():
    clients = _Clients()
    finding = _base_finding("enable_account_pab")
    result = remediate(
        "enable_account_pab",
        finding,
        _settings(2),
        clients.as_dict(),
        allow_apply=True,
    )
    assert result.mode == "APPLY"
    assert result.applied is True
    assert clients.s3.calls == 1


def test_remediate_sensitive_forces_dry_run():
    clients = _Clients()
    finding = _base_finding("enable_org_or_multi_region_cloudtrail")
    result = remediate(
        "enable_org_or_multi_region_cloudtrail",
        finding,
        _settings(2),
        clients.as_dict(),
        allow_apply=True,
    )
    assert result.mode == "DRY_RUN"
    assert result.applied is False


def test_remediate_unknown_action_skips():
    clients = _Clients()
    finding = _base_finding("unknown_action")
    result = remediate("unknown_action", finding, _settings(2), clients.as_dict())
    assert result.mode == "SKIP"
    assert result.error == "not_registered"
@register("enable_org_or_multi_region_cloudtrail")
def _cloudtrail_handler(finding, settings, clients, apply_changes):
    return "Enabled" if apply_changes else "Would enable"
