"""CIS 3.1 - Ensure visibility into unauthorized API calls."""


from datetime import datetime, timedelta, timezone
import time
from typing import Any, Dict, List

from botocore.exceptions import ClientError

from settings import Settings

META = {
    "cis": "3.1",
    "version": ['v1_5', 'v5_0']
}

RECOMMENDED_PATTERNS = (
    '$.errorCode = "UnauthorizedOperation"',
    '$.errorCode = "AccessDenied*"',
)


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for unauthorized API monitoring via metric filter or Lake query."""
    checked_at = datetime.now(timezone.utc)
    mode = settings.unauth_mode.lower()
    if mode not in {"logs", "lake"}:
        mode = "logs"

    try:
        if mode == "lake":
            status, evidence = _evaluate_lake(settings, clients)
        else:
            status, evidence = _evaluate_logs(clients)
    except ClientError as error:
        status = "WARN"
        evidence = {"error": str(error), "mode": mode}

    finding = {
        "id": "CIS-3.1",
        "title": "Monitor unauthorized API activity",
        "cis": "3.1",
        "service": "cloudtrail" if mode == "lake" else "logs",
        "severity": "MEDIUM",
        "status": status,
        "resource_ids": evidence.get("resources", []) if isinstance(evidence, dict) else [],
        "evidence": evidence,
        "remediable": True,
        "remediation_action": "create_metric_filter_alarm_unauth" if mode == "logs" else "",
        "references": [
            "https://docs.aws.amazon.com/securityhub/latest/userguide/cloudwatch-controls.html",
        ],
        "checked_at": checked_at,
    }
    return [finding]


def _evaluate_logs(clients: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
    logs_client = clients["logs"]
    paginator = logs_client.get_paginator("describe_metric_filters")
    matching_filters = []
    for page in paginator.paginate():
        for metric_filter in page.get("metricFilters", []):
            pattern = metric_filter.get("filterPattern", "")
            if _pattern_matches(pattern):
                matching_filters.append(metric_filter.get("filterName"))
    status = "PASS" if matching_filters else "FAIL"
    return status, {"mode": "logs", "filters": matching_filters}


def _evaluate_lake(settings: Settings, clients: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
    window = datetime.now(timezone.utc) - timedelta(days=settings.unauth_window_days)
    start_time = window.strftime("%Y-%m-%dT%H:%M:%SZ")
    excludes = [pattern.strip().lower() for pattern in settings.unauth_exclude_services.split(",") if pattern.strip()]
    threshold = settings.unauth_result_threshold

    client = clients.get("cloudtrail_lake") or clients.get("cloudtraillake")
    if client is None:
        raise ClientError({"Error": {"Code": "MissingClient", "Message": "cloudtrail lake client missing"}}, "StartQuery")

    statement = (
        "SELECT eventSource, count(*) as total FROM events "
        f"WHERE eventTime >= '{start_time}' "
        "AND (errorCode = 'UnauthorizedOperation' OR errorCode LIKE 'AccessDenied%') "
        "GROUP BY eventSource"
    )

    query_id = client.start_query(QueryStatement=statement)["QueryId"]
    while True:
        status = client.get_query_status(QueryId=query_id)["QueryStatus"]
        state = status.get("State")
        if state in {"FINISHED", "FAILED", "CANCELLED"}:
            if state != "FINISHED":
                raise ClientError({"Error": {"Code": state or "QueryError", "Message": "Query did not finish"}}, "GetQueryResults")
            break
        time.sleep(settings.api_backoff)

    response = client.get_query_results(QueryId=query_id)
    rows = response.get("QueryResultRows", [])
    total = 0
    services: Dict[str, int] = {}
    for row in rows:
        data = {cell.get("FieldName"): cell.get("FieldValue") for cell in row.get("Data", [])}
        source = (data.get("eventSource") or "").lower()
        count = int(data.get("total", "0"))
        if any(exclude in source for exclude in excludes):
            continue
        total += count
        services[source] = services.get(source, 0) + count

    status = "PASS" if total <= threshold else "FAIL"
    evidence = {"mode": "lake", "unauthorized_count": total, "services": services, "query_window_days": settings.unauth_window_days}
    return status, evidence


def _pattern_matches(pattern: str) -> bool:
    pattern_lower = pattern.lower()
    return all(keyword in pattern_lower for keyword in ("unauthorized", "access")) or any(
        token in pattern for token in RECOMMENDED_PATTERNS
    )
