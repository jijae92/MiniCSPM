"""CIS 1.22 - Ensure MFA is enabled for all IAM users with console access."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from botocore.exceptions import ClientError

from settings import Settings

META = {
    "cis": "1.22",
    "version": ['v1_5', 'v5_0']
}


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check IAM users with console passwords for MFA enablement."""
    checked_at = datetime.now(timezone.utc)
    iam_client = clients["iam"]
    missing_mfa: List[str] = []
    try:
        paginator = iam_client.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                user_name = user["UserName"]
                if not _has_console_access(iam_client, user_name):
                    continue
                if not _has_mfa_device(iam_client, user_name):
                    missing_mfa.append(user_name)
        status = "PASS" if not missing_mfa else "FAIL"
        evidence = {"users_missing_mfa": missing_mfa}
    except ClientError as error:
        status = "WARN"
        evidence = {"error": str(error)}

    finding = {
        "id": "CIS-1.22",
        "title": "Console users enforce MFA",
        "cis": "1.22",
        "service": "iam",
        "severity": "HIGH",
        "status": status,
        "resource_ids": missing_mfa,
        "evidence": evidence,
        "remediable": False,
        "remediation_action": "",
        "references": [
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_users-self-manage-mfa-and-creds.html",
        ],
        "checked_at": checked_at,
    }
    return [finding]


def _has_console_access(iam_client, user_name: str) -> bool:
    try:
        iam_client.get_login_profile(UserName=user_name)
        return True
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return False
        raise


def _has_mfa_device(iam_client, user_name: str) -> bool:
    devices = iam_client.list_mfa_devices(UserName=user_name).get("MFADevices", [])
    return len(devices) > 0
