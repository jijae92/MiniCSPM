"""CIS 2.1 - CloudTrail enabled in all regions."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from botocore.exceptions import ClientError

from settings import Settings


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Verify at least one multi-region CloudTrail is active."""
    checked_at = datetime.now(timezone.utc)
    cloudtrail = clients["cloudtrail"]
    try:
        response = cloudtrail.describe_trails(includeShadowTrails=True)
        trails = response.get("trailList", [])
        eligible = [trail for trail in trails if trail.get("IsMultiRegionTrail")]
        good_trails = []
        for trail in eligible:
            status = cloudtrail.get_trail_status(Name=trail["TrailARN"])
            if status.get("IsLogging") and trail.get("LogFileValidationEnabled") and trail.get("S3BucketName"):
                good_trails.append(trail["TrailARN"])
        is_pass = len(good_trails) > 0
        finding_status = "PASS" if is_pass else "FAIL"
        evidence = {
            "multi_region_trails": [trail.get("TrailARN") for trail in eligible],
            "good_trails": good_trails,
        }
    except ClientError as error:
        finding_status = "WARN"
        evidence = {"error": str(error)}

    finding = {
        "id": "CIS-2.1",
        "title": "CloudTrail multi-region and logging",
        "cis": "2.1",
        "service": "cloudtrail",
        "severity": "HIGH",
        "status": finding_status,
        "resource_ids": evidence.get("good_trails", []) if isinstance(evidence, dict) else [],
        "evidence": evidence,
        "remediable": True,
        "remediation_action": "enable_org_or_multi_region_cloudtrail",
        "references": [
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/creating-trail-organization.html",
        ],
        "checked_at": checked_at,
    }
    return [finding]
