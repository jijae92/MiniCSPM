"""CIS 2.2 - Ensure CloudTrail log file validation is enabled."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from botocore.exceptions import ClientError

from settings import Settings

META = {
    "cis": "2.2",
    "version": ['v1_5', 'v5_0']
}


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check CloudTrail log validation settings."""
    checked_at = datetime.now(timezone.utc)
    cloudtrail = clients["cloudtrail"]
    try:
        response = cloudtrail.describe_trails(includeShadowTrails=True)
        trails = response.get("trailList", [])
        non_validated = [trail["TrailARN"] for trail in trails if not trail.get("LogFileValidationEnabled")]
        status = "PASS" if trails and not non_validated else "FAIL"
        evidence = {"non_validated_trails": non_validated, "trail_count": len(trails)}
    except ClientError as error:
        status = "WARN"
        evidence = {"error": str(error)}

    finding = {
        "id": "CIS-2.2",
        "title": "CloudTrail log file validation enabled",
        "cis": "2.2",
        "service": "cloudtrail",
        "severity": "MEDIUM",
        "status": status,
        "resource_ids": evidence.get("non_validated_trails", []) if isinstance(evidence, dict) else [],
        "evidence": evidence,
        "remediable": True,
        "remediation_action": "update_trail_validation",
        "references": [
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html",
        ],
        "checked_at": checked_at,
    }
    return [finding]
