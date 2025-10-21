import json
import pytest
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from engine import Engine, CheckOutcome
from models import ExecutionContext, Finding
from settings import Settings


def make_settings() -> Settings:
    return Settings(
        table_name="MiniCspmResults",
        report_bucket="mini-cspm-local",
        enable_pdf=False,
        enable_html=False,
        auto_remediate=2,
        csv_prefix="reports/",
        html_prefix="reports/",
        pdf_prefix="reports/",
        fail_on="HIGH",
        schedule_expression="rate(24 hours)",
        account_id="123456789012",
        aws_region="us-east-1",
        max_check_workers=1,
        enable_presigned_urls=False,
        score_threshold=80,
        event_bus_name="mini-cspm-bus",
        remediation_apply_env_enabled=True,
        remediation_apply_parameter="/mini-cspm/demo-apply",
        cis_version="v1_5",
    )


def test_engine_runs_all_checks():
    settings = make_settings()
    events = _EventsClient()
    engine = Engine(settings=settings, s3_client=_FakeS3(), events_client=events, ssm_client=_SSMClient(True))
    context = ExecutionContext(
        account_id="123456789012",
        region="us-east-1",
        invoked_at=datetime.now(timezone.utc),
    )
    clients = _fake_clients()
    result = engine.run_all_checks(context=context, clients=clients)
    assert result.score.total == 10
    assert len(result.findings) == 10
    pab_finding = next(f for f in result.findings if f.id == "CIS-5.1")
    remediations = pab_finding.evidence.get("remediations")
    assert remediations is not None
    assert remediations[0]["mode"] == "APPLY"
    assert remediations[0]["applied"] is True
    assert clients["s3"].put_calls == 1
    assert len(events.entries) == 0


def test_engine_scoring_weighted():
    settings = make_settings()
    engine = Engine(settings=settings, s3_client=_FakeS3(), ssm_client=_SSMClient(True))
    outcomes = [
        CheckOutcome(name=f"pass_{idx}", findings=[], status="PASS") for idx in range(7)
    ] + [
        CheckOutcome(name=f"fail_{idx}", findings=[], status="FAIL") for idx in range(3)
    ]
    score = engine._score_outcomes(outcomes)  # pylint: disable=protected-access
    assert score.total == 10
    assert score.passed == 7
    assert score.failed == 3
    assert score.weighted == 70


def test_alert_emission_thresholds(monkeypatch):
    settings = make_settings()
    events = _EventsClient()
    engine = Engine(settings=settings, s3_client=_FakeS3(), events_client=events, ssm_client=_SSMClient(True))
    context = ExecutionContext(
        account_id="123456789012",
        region="us-east-1",
        invoked_at=datetime.now(timezone.utc),
    )

    # Force findings to include one high FAIL and low score via stubbing
    failing_finding = Finding(
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
        checked_at=datetime.now(timezone.utc),
    )

    monkeypatch.setattr(
        engine,
        "_execute_checks",
        lambda check_ids, context, clients: [
            CheckOutcome(name=check_ids[0] if check_ids else "mock", findings=[failing_finding], status="FAIL")
        ],
    )
    clients = _fake_clients()
    result = engine.run_all_checks(context=context, clients=clients)
    monkeypatch.setattr(engine, "_write_csv_report", lambda result: ("reports/test.csv", None))
    with pytest.raises(RuntimeError):
        engine.publish_reports(result)

    assert len(events.entries) == 1
    detail = events.entries[0]["Detail"]
    assert detail["metrics"]["high_failures"] >= 1


def _fake_clients():
    return {
        "iam": _IAMClient(),
        "cloudtrail": _CloudTrailClient(),
        "logs": _LogsClient(),
        "ec2": _EC2Client(),
        "s3": _S3ControlClient(),
        "cloudwatch": _CloudWatchClient(),
    }


class _IAMClient:
    def __init__(self):
        self.policy_updates = 0

    def get_account_summary(self):
        return {"SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}}

    def get_account_password_policy(self):
        return {
            "PasswordPolicy": {
                "MinimumPasswordLength": 14,
                "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True,
                "RequireSymbols": True,
                "RequireNumbers": True,
                "PasswordReusePrevention": 24,
                "MaxPasswordAge": 90,
            }
        }

    def get_paginator(self, name):
        assert name == "list_users"
        return _SimplePaginator([{"Users": []}])

    def get_login_profile(self, **kwargs):
        raise ClientError({"Error": {"Code": "NoSuchEntity"}}, "GetLoginProfile")

    def list_mfa_devices(self, **kwargs):  # pragma: no cover - not used in pass path
        return {"MFADevices": []}

    def update_account_password_policy(self, **kwargs):
        self.policy_updates += 1
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


class _CloudTrailClient:
    def describe_trails(self, **kwargs):
        return {
            "trailList": [
                {
                    "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/org",
                    "IsMultiRegionTrail": True,
                    "LogFileValidationEnabled": True,
                    "S3BucketName": "trail-bucket",
                    "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/abc",
                }
            ]
        }

    def get_trail_status(self, **kwargs):
        return {"IsLogging": True}


class _LogsClient:
    def __init__(self):
        self.put_calls = 0

    def get_paginator(self, name):
        assert name == "describe_metric_filters"
        return _SimplePaginator(
            [
                {
                    "metricFilters": [
                        {
                            "filterName": "unauthorized-metric",
                            "filterPattern": "{ $.errorCode = \"UnauthorizedOperation\" }",
                        }
                    ]
                }
            ]
        )

    def put_metric_filter(self, **kwargs):
        self.put_calls += 1
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


class _EC2Client:
    def __init__(self):
        self.revoke_calls = []

    def describe_security_groups(self):
        return {"SecurityGroups": []}

    def revoke_security_group_ingress(self, **kwargs):
        self.revoke_calls.append(kwargs)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


class _S3ControlClient:
    def get_public_access_block(self, **kwargs):
        return {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            }
        }

    def __init__(self):
        self.put_calls = 0

    def put_public_access_block(self, **kwargs):
        self.put_calls += 1
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


class _CloudWatchClient:
    def put_metric_alarm(self, **kwargs):
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


class _FakeS3:
    def put_object(self, **kwargs):
        return None

    def generate_presigned_url(self, **kwargs):
        return "https://example.com"


class _EventsClient:
    def __init__(self):
        self.entries = []

    def put_events(self, Entries):
        for entry in Entries:
            # store parsed detail for assertions
            parsed = dict(entry)
            parsed["Detail"] = json.loads(entry["Detail"])
            self.entries.append(parsed)


class _SSMClient:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def get_parameter(self, Name):
        value = "true" if self.enabled else "false"
        return {"Parameter": {"Name": Name, "Value": value}}


class _SimplePaginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **kwargs):
        for page in self.pages:
            yield page
