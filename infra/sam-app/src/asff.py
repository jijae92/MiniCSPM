
"""Convert MiniCSPM findings to AWS Security Finding Format (ASFF)."""

from __future__ import annotations

from datetime import timezone
from typing import Dict

from models import Finding

_ASFF_TYPES = ["Software and Configuration Checks/AWS Security Best Practices"]
_SEVERITY_LABEL = {
    "CRITICAL": (90, "CRITICAL"),
    "HIGH": (70, "HIGH"),
    "MEDIUM": (40, "MEDIUM"),
    "LOW": (10, "LOW"),
    "INFORMATIONAL": (0, "INFORMATIONAL"),
}


def finding_to_asff(
    finding: Finding,
    account_id: str,
    region: str,
    product_arn: str,
    cis_version: str,
) -> Dict[str, object]:
    """Translate a MiniCSPM finding into an ASFF-compatible structure."""
    checked_at = finding.checked_at.astimezone(timezone.utc)
    iso_time = checked_at.isoformat().replace("+00:00", "Z")
    severity_score, severity_label = _SEVERITY_LABEL.get(finding.severity.upper(), (10, "LOW"))
    normalized_version = cis_version.replace("_", ".")
    requirement = f"CIS-AWS-{finding.cis}(v{normalized_version[1:]})" if finding.cis else None
    requirement_list = [requirement] if requirement else []

    resource_ids = finding.resource_ids or [account_id]
    resources = [
        {
            "Type": "AwsAccount" if rid == account_id else "Other",
            "Id": rid,
            "Partition": "aws",
            "Region": region,
        }
        for rid in resource_ids
    ]

    description = finding.title
    if finding.evidence:
        description = f"{finding.title} | Evidence: {finding.evidence}"[:1024]

    finding_id = f"{account_id}:{finding.id}:{checked_at.strftime('%Y%m%dT%H%M%SZ')}"

    recommendation = finding.remediation_action or ""

    asff = {
        "SchemaVersion": "2018-10-08",
        "Id": finding_id,
        "ProductArn": product_arn,
        "GeneratorId": finding.id,
        "AwsAccountId": account_id,
        "Types": _ASFF_TYPES,
        "CreatedAt": iso_time,
        "UpdatedAt": iso_time,
        "Severity": {"Label": severity_label, "Normalized": severity_score},
        "Title": finding.title,
        "Description": description,
        "SourceUrl": finding.references[0] if finding.references else None,
        "Resources": resources,
        "RecordState": "ACTIVE",
        "Workflow": {"Status": "NEW"},
        "Compliance": {
            "Status": "FAILED" if finding.status == "FAIL" else "WARNING",
            "RelatedRequirements": requirement_list,
        },
        "ProductFields": {
            "MiniCSPM/Service": finding.service,
            "MiniCSPM/Severity": finding.severity,
            "MiniCSPM/Status": finding.status,
            "MiniCSPM/CisVersion": cis_version,
        },
    }

    if recommendation:
        asff["Remediation"] = {"Recommendation": {"Text": recommendation}}
    if not asff.get("SourceUrl"):
        asff.pop("SourceUrl", None)

    return asff
