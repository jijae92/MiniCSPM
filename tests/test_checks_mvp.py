from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List

import pytest
from botocore.exceptions import ClientError

from checks import (
    cis_1_1_root_mfa,
    cis_1_2_no_root_keys,
    cis_1_5_password_policy,
    cis_1_22_mfa_console_users,
    cis_2_1_cloudtrail_all_regions,
    cis_2_2_cloudtrail_log_validation,
    cis_2_3_cloudtrail_encrypted_kms,
    cis_3_1_unauth_api_metric_filter,
    cis_4_1_sg_no_0_0_0_0_22_3389,
    cis_5_1_s3_account_pab_on,
)
from settings import Settings


@pytest.fixture
def settings() -> Settings:
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
        account_id="123456789012",
        aws_region="us-east-1",
    )


def test_cis_1_1_root_mfa_pass(settings):
    clients = make_clients(iam=IAMClientStub(summary_map={"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}))
    finding = cis_1_1_root_mfa.run(settings=settings, clients=clients)[0]
    assert finding["status"] == "PASS"


def test_cis_1_1_root_mfa_fail(settings):
    clients = make_clients(iam=IAMClientStub(summary_map={"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 0}))
    finding = cis_1_1_root_mfa.run(settings=settings, clients=clients)[0]
    assert finding["status"] == "FAIL"


def test_cis_1_2_no_root_keys_fail(settings):
    clients = make_clients(iam=IAMClientStub(summary_map={"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 1}))
    finding = cis_1_2_no_root_keys.run(settings=settings, clients=clients)[0]
    assert finding["status"] == "FAIL"


def test_cis_1_2_no_root_keys_pass(settings):
    clients = make_clients(iam=IAMClientStub(summary_map={"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}))
    finding = cis_1_2_no_root_keys.run(settings=settings, clients=clients)[0]
    assert finding["status"] == "PASS"


def test_cis_1_5_password_policy_pass(settings):
    clients = make_clients(iam=IAMClientStub())
    finding = cis_1_5_password_policy.run(settings=settings, clients=clients)[0]
    assert finding["status"] == "PASS"


def test_cis_1_5_password_policy_fail(settings):
    weak_policy = {
        "MinimumPasswordLength": 10,
        "RequireUppercaseCharacters": True,
        "RequireLowercaseCharacters": True,
        "RequireSymbols": False,
        "RequireNumbers": True,
        "PasswordReusePrevention": 10,
        "MaxPasswordAge": 120,
    }
    clients = make_clients(iam=IAMClientStub(password_policy=weak_policy))
    finding = cis_1_5_password_policy.run(settings=settings, clients=clients)[0]
    assert finding["status"] == "FAIL"


def test_cis_1_22_mfa_console_users_fail(settings):
    iam = IAMClientStub(
        users=[{"UserName": "alice"}],
        console_users={"alice"},
        mfa_users=set(),
    )
    clients = make_clients(iam=iam)
    finding = cis_1_22_mfa_console_users.run(settings=settings, clients=clients)[0]
    assert finding["status"] == "FAIL"
    assert "alice" in finding["evidence"]["users_missing_mfa"]


def test_cis_1_22_mfa_console_users_pass(settings):
    iam = IAMClientStub(
        users=[{"UserName": "bob"}],
        console_users={"bob"},
        mfa_users={"bob"},
    )
    clients = make_clients(iam=iam)
    finding = cis_1_22_mfa_console_users.run(settings=settings, clients=clients)[0]
    assert finding["status"] == "PASS"


def test_cis_2_1_cloudtrail_fail(settings):
    trails = [
        {
            "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/bad",
            "IsMultiRegionTrail": True,
            "LogFileValidationEnabled": True,
            "S3BucketName": "bucket",
        }
    ]
    cloudtrail = CloudTrailClientStub(trails=trails, logging_trails=set())
    clients = make_clients(cloudtrail=cloudtrail)
    finding = cis_2_1_cloudtrail_all_regions.run(settings=settings, clients=clients)[0]
    assert finding["status"] == "FAIL"


def test_cis_2_1_cloudtrail_pass(settings):
    trail_arn = "arn:aws:cloudtrail:us-east-1:123456789012:trail/good"
    trails = [
        {
            "TrailARN": trail_arn,
            "IsMultiRegionTrail": True,
            "LogFileValidationEnabled": True,
            "S3BucketName": "bucket",
        }
    ]
    cloudtrail = CloudTrailClientStub(trails=trails, logging_trails={trail_arn})
    clients = make_clients(cloudtrail=cloudtrail)
    finding = cis_2_1_cloudtrail_all_regions.run(settings=settings, clients=clients)[0]
    assert finding["status"] == "PASS"


def test_cis_2_2_cloudtrail_validation_fail(settings):
    trails = [
        {
            "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/no-validation",
            "LogFileValidationEnabled": False,
        }
    ]
    clients = make_clients(cloudtrail=CloudTrailClientStub(trails=trails, logging_trails=set()))
    finding = cis_2_2_cloudtrail_log_validation.run(settings=settings, clients=clients)[0]
    assert finding["status"] == "FAIL"


def test_cis_2_2_cloudtrail_validation_pass(settings):
    trails = [
        {
            "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/valid",
            "LogFileValidationEnabled": True,
        }
    ]
    clients = make_clients(cloudtrail=CloudTrailClientStub(trails=trails, logging_trails=set()))
    finding = cis_2_2_cloudtrail_log_validation.run(settings=settings, clients=clients)[0]
    assert finding["status"] == "PASS"


def test_cis_2_3_cloudtrail_kms_fail(settings):
    trails = [
        {
            "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/no-kms",
            "KmsKeyId": None,
        }
    ]
    clients = make_clients(cloudtrail=CloudTrailClientStub(trails=trails, logging_trails=set()))
    finding = cis_2_3_cloudtrail_encrypted_kms.run(settings=settings, clients=clients)[0]
    assert finding["status"] == "FAIL"


def test_cis_2_3_cloudtrail_kms_pass(settings):
    trails = [
        {
            "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/kms",
            "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/abc",
        }
    ]
    clients = make_clients(cloudtrail=CloudTrailClientStub(trails=trails, logging_trails=set()))
    finding = cis_2_3_cloudtrail_encrypted_kms.run(settings=settings, clients=clients)[0]
    assert finding["status"] == "PASS"


def test_cis_3_1_metric_filter_fail(settings):
    logs_client = LogsClientStub(filters=[])
    clients = make_clients(logs=logs_client)
    finding = cis_3_1_unauth_api_metric_filter.run(settings=settings, clients=clients)[0]
    assert finding["status"] == "FAIL"


def test_cis_3_1_metric_filter_pass(settings):
    logs_client = LogsClientStub(filters=[{"filterName": "match", "filterPattern": "$.errorCode = \"UnauthorizedOperation\""}])
    clients = make_clients(logs=logs_client)
    finding = cis_3_1_unauth_api_metric_filter.run(settings=settings, clients=clients)[0]
    assert finding["status"] == "PASS"


def test_cis_4_1_security_groups_fail(settings):
    sg = [
        {
            "GroupId": "sg-123",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                }
            ],
        }
    ]
    clients = make_clients(ec2=EC2ClientStub(security_groups=sg))
    finding = cis_4_1_sg_no_0_0_0_0_22_3389.run(settings=settings, clients=clients)[0]
    assert finding["status"] == "FAIL"


def test_cis_4_1_security_groups_pass(settings):
    clients = make_clients(ec2=EC2ClientStub(security_groups=[]))
    finding = cis_4_1_sg_no_0_0_0_0_22_3389.run(settings=settings, clients=clients)[0]
    assert finding["status"] == "PASS"


def test_cis_5_1_pab_fail(settings):
    s3 = S3ControlClientStub(config={"BlockPublicAcls": True, "IgnorePublicAcls": False})
    clients = make_clients(s3=s3)
    finding = cis_5_1_s3_account_pab_on.run(settings=settings, clients=clients)[0]
    assert finding["status"] == "FAIL"


def test_cis_5_1_pab_pass(settings):
    s3 = S3ControlClientStub()
    clients = make_clients(s3=s3)
    finding = cis_5_1_s3_account_pab_on.run(settings=settings, clients=clients)[0]
    assert finding["status"] == "PASS"


def make_clients(**overrides) -> Dict[str, object]:
    base = {service: NullClient(service) for service in ("iam", "cloudtrail", "logs", "ec2", "s3")}
    base.update(overrides)
    return base


class NullClient:
    def __init__(self, service: str):
        self.service = service

    def __getattr__(self, item):  # pragma: no cover - safeguards unexpected calls
        raise AssertionError(f"Unexpected call to {self.service}.{item}")


@dataclass
class IAMClientStub:
    summary_map: Dict[str, int] | None = None
    password_policy: Dict[str, object] | None = None
    users: List[Dict[str, object]] | None = None
    console_users: Iterable[str] | None = None
    mfa_users: Iterable[str] | None = None

    def __post_init__(self):
        if self.summary_map is None:
            self.summary_map = {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}
        if self.password_policy is None:
            self.password_policy = {
                "MinimumPasswordLength": 14,
                "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True,
                "RequireSymbols": True,
                "RequireNumbers": True,
                "PasswordReusePrevention": 24,
                "MaxPasswordAge": 90,
            }
        self.users = list(self.users or [])
        self.console_users = set(self.console_users or set())
        self.mfa_users = set(self.mfa_users or set())

    def get_account_summary(self):
        return {"SummaryMap": self.summary_map}

    def get_account_password_policy(self):
        if self.password_policy is None:
            raise ClientError({"Error": {"Code": "NoSuchEntity"}}, "GetAccountPasswordPolicy")
        return {"PasswordPolicy": self.password_policy}

    def get_paginator(self, name):
        assert name == "list_users"
        return SimplePaginator({"Users": self.users})

    def get_login_profile(self, UserName):
        if UserName in self.console_users:
            return {}
        raise ClientError({"Error": {"Code": "NoSuchEntity"}}, "GetLoginProfile")

    def list_mfa_devices(self, UserName):
        if UserName in self.mfa_users:
            return {"MFADevices": [{"SerialNumber": "arn"}]}
        return {"MFADevices": []}


class CloudTrailClientStub:
    def __init__(self, trails: List[Dict[str, object]], logging_trails: Iterable[str]):
        self.trails = trails
        self.logging_trails = set(logging_trails)

    def describe_trails(self, **kwargs):
        return {"trailList": self.trails}

    def get_trail_status(self, Name):
        return {"IsLogging": Name in self.logging_trails}


class LogsClientStub:
    def __init__(self, filters: List[Dict[str, object]]):
        self.filters = filters

    def get_paginator(self, name):
        assert name == "describe_metric_filters"
        return SimplePaginator({"metricFilters": self.filters})


class EC2ClientStub:
    def __init__(self, security_groups: List[Dict[str, object]]):
        self.security_groups = security_groups

    def describe_security_groups(self):
        return {"SecurityGroups": self.security_groups}


class S3ControlClientStub:
    def __init__(self, config: Dict[str, bool] | None = None):
        if config is None:
            config = {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        self.config = config

    def get_public_access_block(self, **kwargs):
        missing = {flag: False for flag in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}
        missing.update(self.config)
        return {"PublicAccessBlockConfiguration": missing}


class SimplePaginator:
    def __init__(self, *pages):
        self.pages = pages

    def paginate(self, **kwargs):
        for page in self.pages:
            yield page
