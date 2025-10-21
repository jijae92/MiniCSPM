"""CIS 2.3 - Ensure CloudTrail logs encrypted with KMS CMKs."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from botocore.exceptions import ClientError

from settings import Settings


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Validate CloudTrail trails use KMS encryption."""
    checked_at = datetime.now(timezone.utc)
    cloudtrail = clients["cloudtrail"]
    try:
        response = cloudtrail.describe_trails(includeShadowTrails=True)
        trails = response.get("trailList", [])
        missing_kms = [trail["TrailARN"] for trail in trails if not trail.get("KmsKeyId")]
        status = "PASS" if trails and not missing_kms else "FAIL"
        evidence = {"missing_kms_trails": missing_kms, "trail_count": len(trails)}
    except ClientError as error:
        status = "WARN"
        evidence = {"error": str(error)}

    finding = {
        "id": "CIS-2.3",
        "title": "CloudTrail logs encrypted with KMS",
        "cis": "2.3",
        "service": "cloudtrail",
        "severity": "MEDIUM",
        "status": status,
        "resource_ids": evidence.get("missing_kms_trails", []) if isinstance(evidence, dict) else [],
        "evidence": evidence,
        "remediable": True,
        "remediation_action": "attach_kms_to_trail",
        "references": [
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-kms.html",
        ],
        "checked_at": checked_at,
    }
    return [finding]
