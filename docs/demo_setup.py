"""Automated AWS demo misconfiguration helper.

This script is intentionally disruptive and should only be executed in a non-production demo account.
It prepares the following insecure states:
  * Security Group with TCP 22/3389 open to 0.0.0.0/0 (tagged Demo=true)
  * Account-level S3 Block Public Access disabled
  * Weak IAM password policy (length 8, no symbols)
  * CloudTrail log file validation turned off on the first available trail

Run `python docs/demo_reset.py` (to be provided by the operator) afterwards to restore secure defaults.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from typing import Optional

import boto3
from botocore.exceptions import ClientError


@dataclass
class DemoConfig:
    region: str
    sg_name: str = "mini-cspm-demo-sg"
    vpc_id: Optional[str] = None


def parse_args(argv: list[str]) -> DemoConfig:
    parser = argparse.ArgumentParser(description="Create insecure demo baseline for MiniCSPM")
    parser.add_argument("--region", default="us-east-1", help="Target AWS region")
    parser.add_argument("--sg-name", default="mini-cspm-demo-sg", help="Name for the demo security group")
    parser.add_argument("--vpc-id", help="VPC to create the demo security group in (defaults to default VPC)")
    args = parser.parse_args(argv)
    return DemoConfig(region=args.region, sg_name=args.sg_name, vpc_id=args.vpc_id)


def main(argv: list[str] | None = None) -> int:
    cfg = parse_args(argv or sys.argv[1:])
    print("[INFO] Using region", cfg.region)

    session = boto3.Session(region_name=cfg.region)
    ec2 = session.client("ec2")
    s3control = session.client("s3control")
    iam = session.client("iam")
    cloudtrail = session.client("cloudtrail")

    account_id = session.client("sts").get_caller_identity()["Account"]
    vpc_id = cfg.vpc_id or _get_default_vpc(ec2)
    if not vpc_id:
        print("[ERROR] Unable to determine default VPC. Specify --vpc-id", file=sys.stderr)
        return 2

    try:
        sg_id = _create_open_sg(ec2, cfg.sg_name, vpc_id)
        print(f"[OK] Created/opened security group {sg_id}")
    except ClientError as exc:
        print(f"[WARN] Security group setup failed: {exc}")

    try:
        _disable_public_access_block(s3control, account_id)
        print("[OK] Disabled account-level S3 Block Public Access (PAB)")
    except ClientError as exc:
        print(f"[WARN] Failed to disable S3 PAB: {exc}")

    try:
        _set_weak_password_policy(iam)
        print("[OK] Applied weak IAM password policy")
    except ClientError as exc:
        print(f"[WARN] Failed to weaken password policy: {exc}")

    try:
        trail_name = _disable_trail_validation(cloudtrail)
        if trail_name:
            print(f"[OK] Disabled CloudTrail log validation on {trail_name}")
        else:
            print("[INFO] No CloudTrail trails detected; skipped log validation change")
    except ClientError as exc:
        print(f"[WARN] Failed to update CloudTrail: {exc}")

    print("\n[NOTICE] Demo misconfiguration complete. After running MiniCSPM scans, execute your reset script to restore secure settings.")
    return 0


def _get_default_vpc(ec2_client) -> Optional[str]:
    response = ec2_client.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
    vpcs = response.get("Vpcs", [])
    return vpcs[0]["VpcId"] if vpcs else None


def _create_open_sg(ec2_client, sg_name: str, vpc_id: str) -> str:
    existing = ec2_client.describe_security_groups(Filters=[{"Name": "group-name", "Values": [sg_name]}]).get("SecurityGroups")
    if existing:
        sg_id = existing[0]["GroupId"]
    else:
        response = ec2_client.create_security_group(GroupName=sg_name, Description="MiniCSPM demo insecure SG", VpcId=vpc_id)
        sg_id = response["GroupId"]
    ec2_client.create_tags(Resources=[sg_id], Tags=[{"Key": "Demo", "Value": "true"}])

    ingress_rules = [
        {
            "IpProtocol": "tcp",
            "FromPort": port,
            "ToPort": port,
            "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "Demo insecure open access"}],
        }
        for port in (22, 3389)
    ]
    ec2_client.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=ingress_rules)
    return sg_id


def _disable_public_access_block(s3control_client, account_id: str) -> None:
    s3control_client.delete_public_access_block(AccountId=account_id)


def _set_weak_password_policy(iam_client) -> None:
    iam_client.update_account_password_policy(
        MinimumPasswordLength=8,
        RequireSymbols=False,
        RequireNumbers=True,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        PasswordReusePrevention=0,
        MaxPasswordAge=0,
        AllowUsersToChangePassword=True,
    )


def _disable_trail_validation(cloudtrail_client) -> Optional[str]:
    trails = cloudtrail_client.describe_trails().get("trailList", [])
    if not trails:
        return None
    trail = trails[0]
    name = trail.get("Name") or trail.get("TrailARN")
    if not name:
        return None
    cloudtrail_client.update_trail(Name=name, LogFileValidationEnabled=False)
    return name


if __name__ == "__main__":
    raise SystemExit(main())
