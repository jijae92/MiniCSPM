"""CIS 1.2 - Ensure no root access keys exist."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from botocore.exceptions import ClientError

from settings import Settings

META = {
    "cis": "1.2",
    "version": ['v1_5', 'v5_0']
}


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for active root access keys."""
    checked_at = datetime.now(timezone.utc)
    account_id = settings.account_id or "000000000000"
    try:
        summary = clients["iam"].get_account_summary()
        present = summary.get("SummaryMap", {}).get("AccountAccessKeysPresent", 0)
        status = "PASS" if present == 0 else "FAIL"
        evidence = {"access_keys_present": int(present)}
    except ClientError as error:  # pragma: no cover
        status = "WARN"
        evidence = {"error": str(error)}

    finding = {
        "id": "CIS-1.2",
        "title": "Root access keys removed",
        "cis": "1.2",
        "service": "iam",
        "severity": "HIGH",
        "status": status,
        "resource_ids": [account_id],
        "evidence": evidence,
        "remediable": False,
        "remediation_action": "",
        "references": [
            "https://docs.aws.amazon.com/general/latest/gr/root-user-best-practices.html",
        ],
        "checked_at": checked_at,
    }
    return [finding]
