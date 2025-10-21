"""CIS 5.1 - S3 Block Public Access for the account is enabled."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from botocore.exceptions import ClientError

from settings import Settings

META = {
    "cis": "5.1",
    "version": ['v1_5', 'v5_0']
}

PAB_FLAGS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check account-level S3 Block Public Access configuration."""
    checked_at = datetime.now(timezone.utc)
    account_id = settings.account_id or "000000000000"
    try:
        response = clients["s3"].get_public_access_block(AccountId=account_id)
        config = response.get("PublicAccessBlockConfiguration", {})
        all_enabled = all(config.get(flag, False) for flag in PAB_FLAGS)
        status = "PASS" if all_enabled else "FAIL"
        evidence = {flag: bool(config.get(flag, False)) for flag in PAB_FLAGS}
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "NoSuchPublicAccessBlockConfiguration":
            status = "FAIL"
            evidence = {"error": "Public access block configuration missing"}
        else:
            status = "WARN"
            evidence = {"error": str(error)}

    finding = {
        "id": "CIS-5.1",
        "title": "Account-level S3 public access block enabled",
        "cis": "5.1",
        "service": "s3",
        "severity": "HIGH",
        "status": status,
        "resource_ids": [account_id],
        "evidence": evidence,
        "remediable": True,
        "remediation_action": "enable_account_pab",
        "references": [
            "https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html",
        ],
        "checked_at": checked_at,
    }
    return [finding]
