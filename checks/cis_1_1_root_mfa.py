"""CIS 1.1 - Root account MFA enabled."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from botocore.exceptions import ClientError

from settings import Settings

META = {
    "cis": "1.1",
    "version": ['v1_5', 'v5_0']
}


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Validate that the root account has MFA enforced."""
    checked_at = datetime.now(timezone.utc)
    account_id = settings.account_id or "000000000000"
    try:
        summary = clients["iam"].get_account_summary()
        summary_map = summary.get("SummaryMap", {})
        mfa_enabled = summary_map.get("AccountMFAEnabled", 0) == 1
        status = "PASS" if mfa_enabled else "FAIL"
        evidence = {"account_mfa_enabled": int(summary_map.get("AccountMFAEnabled", 0))}
    except ClientError as error:  # pragma: no cover - handled in WARN test
        status = "WARN"
        evidence = {"error": str(error)}
    except Exception as error:  # pragma: no cover
        status = "WARN"
        evidence = {"error": str(error)}

    finding = {
        "id": "CIS-1.1",
        "title": "Root account MFA enabled",
        "cis": "1.1",
        "service": "iam",
        "severity": "HIGH",
        "status": status,
        "resource_ids": [account_id],
        "evidence": evidence,
        "remediable": False,
        "remediation_action": "",
        "references": [
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
        ],
        "checked_at": checked_at,
    }
    return [finding]
