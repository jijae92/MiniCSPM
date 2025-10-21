"""Restore secure defaults after running docs/demo_setup.py."""

from __future__ import annotations

import argparse
import sys
from typing import Optional

import boto3
from botocore.exceptions import ClientError


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Reset resources created by demo_setup")
    parser.add_argument("--region", default="us-east-1", help="Target AWS region")
    parser.add_argument("--sg-name", default="mini-cspm-demo-sg", help="Security group name to clean up")
    parser.add_argument("--account-id", help="Account ID (optional, inferred via STS)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    session = boto3.Session(region_name=args.region)
    ec2 = session.client("ec2")
    s3control = session.client("s3control")
    iam = session.client("iam")
    cloudtrail = session.client("cloudtrail")
    sts = session.client("sts")
    account_id = args.account_id or sts.get_caller_identity()["Account"]

    try:
        _revoke_demo_sg(ec2, args.sg_name)
        print("[OK] Demo security group cleanup complete")
    except ClientError as exc:
        print(f"[WARN] Security group cleanup failed: {exc}")

    try:
        _restore_pab(s3control, account_id)
        print("[OK] Restored S3 Block Public Access")
    except ClientError as exc:
        print(f"[WARN] Failed to restore PAB: {exc}")

    try:
        _restore_password_policy(iam)
        print("[OK] Restored strong IAM password policy")
    except ClientError as exc:
        print(f"[WARN] Failed to restore password policy: {exc}")

    try:
        _enable_trail_validation(cloudtrail)
        print("[OK] Re-enabled CloudTrail log validation")
    except ClientError as exc:
        print(f"[WARN] Failed to update CloudTrail: {exc}")

    return 0


def _revoke_demo_sg(ec2_client, sg_name: str) -> None:
    response = ec2_client.describe_security_groups(Filters=[{"Name": "group-name", "Values": [sg_name]}])
    groups = response.get("SecurityGroups", [])
    if not groups:
        return
    sg_id = groups[0]["GroupId"]
    ec2_client.revoke_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": port,
                "ToPort": port,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
            for port in (22, 3389)
        ],
    )
    ec2_client.delete_security_group(GroupId=sg_id)


def _restore_pab(s3control_client, account_id: str) -> None:
    s3control_client.put_public_access_block(
        AccountId=account_id,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )


def _restore_password_policy(iam_client) -> None:
    iam_client.update_account_password_policy(
        MinimumPasswordLength=14,
        RequireSymbols=True,
        RequireNumbers=True,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        PasswordReusePrevention=24,
        MaxPasswordAge=90,
        AllowUsersToChangePassword=True,
    )


def _enable_trail_validation(cloudtrail_client) -> None:
    trails = cloudtrail_client.describe_trails().get("trailList", [])
    for trail in trails:
        name = trail.get("Name") or trail.get("TrailARN")
        if name:
            cloudtrail_client.update_trail(Name=name, LogFileValidationEnabled=True)


if __name__ == "__main__":
    raise SystemExit(main())
