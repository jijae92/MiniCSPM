"""CIS 1.5 - Ensure IAM password policy requires minimum length 14+."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from botocore.exceptions import ClientError

from settings import Settings

META = {
    "cis": "1.5",
    "version": ['v1_5', 'v5_0']
}

REQUIRED_FLAGS = (
    "RequireUppercaseCharacters",
    "RequireLowercaseCharacters",
    "RequireSymbols",
    "RequireNumbers",
)


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluate IAM password policy for strength requirements."""
    checked_at = datetime.now(timezone.utc)
    account_id = settings.account_id or "000000000000"
    try:
        response = clients["iam"].get_account_password_policy()
        policy = response.get("PasswordPolicy", {})
        meets_min_length = policy.get("MinimumPasswordLength", 0) >= 14
        meets_expiry = policy.get("MaxPasswordAge", 0) and policy["MaxPasswordAge"] <= 90
        meets_reuse = policy.get("PasswordReusePrevention", 0) >= 24
        meets_flags = all(policy.get(flag, False) for flag in REQUIRED_FLAGS)
        is_pass = all([meets_min_length, meets_expiry, meets_reuse, meets_flags])
        status = "PASS" if is_pass else "FAIL"
        evidence = {
            "minimum_length": policy.get("MinimumPasswordLength"),
            "max_password_age": policy.get("MaxPasswordAge"),
            "password_reuse_prevention": policy.get("PasswordReusePrevention"),
            "flags": {flag: bool(policy.get(flag, False)) for flag in REQUIRED_FLAGS},
        }
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "NoSuchEntity":
            status = "FAIL"
            evidence = {"error": "Password policy not set"}
        else:  # pragma: no cover
            status = "WARN"
            evidence = {"error": str(error)}

    finding = {
        "id": "CIS-1.5",
        "title": "Enforce strong IAM password policy",
        "cis": "1.5",
        "service": "iam",
        "severity": "MEDIUM",
        "status": status,
        "resource_ids": [account_id],
        "evidence": evidence,
        "remediable": True,
        "remediation_action": "set_strong_password_policy",
        "references": [
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html",
        ],
        "checked_at": checked_at,
    }
    return [finding]
