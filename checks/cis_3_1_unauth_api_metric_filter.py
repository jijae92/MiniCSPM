"""CIS 3.1 - Ensure a log metric filter exists for unauthorized API calls."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from botocore.exceptions import ClientError

from settings import Settings

RECOMMENDED_PATTERNS = (
    "$.errorCode = \"UnauthorizedOperation\"",
    "$.errorCode = \"AccessDenied*\"",
)


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check CloudWatch Logs metric filters for unauthorized API call detection."""
    checked_at = datetime.now(timezone.utc)
    logs_client = clients["logs"]
    try:
        paginator = logs_client.get_paginator("describe_metric_filters")
        matching_filters = []
        for page in paginator.paginate():
            for metric_filter in page.get("metricFilters", []):
                pattern = metric_filter.get("filterPattern", "")
                if _pattern_matches(pattern):
                    matching_filters.append(metric_filter.get("filterName"))
        status = "PASS" if matching_filters else "FAIL"
        evidence = {"filters": matching_filters}
    except ClientError as error:
        status = "WARN"
        evidence = {"error": str(error)}

    finding = {
        "id": "CIS-3.1",
        "title": "Metric filter for unauthorized API calls",
        "cis": "3.1",
        "service": "logs",
        "severity": "MEDIUM",
        "status": status,
        "resource_ids": evidence.get("filters", []) if isinstance(evidence, dict) else [],
        "evidence": evidence,
        "remediable": True,
        "remediation_action": "create_metric_filter_alarm_unauth",
        "references": [
            "https://docs.aws.amazon.com/securityhub/latest/userguide/cloudwatch-controls.html",
        ],
        "checked_at": checked_at,
    }
    return [finding]


def _pattern_matches(pattern: str) -> bool:
    pattern_lower = pattern.lower()
    return all(keyword.lower() in pattern_lower for keyword in ("unauthorized", "access")) or any(
        token in pattern for token in RECOMMENDED_PATTERNS
    )
