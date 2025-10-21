"""AWS Lambda schedule entrypoint for Mini-CSPM."""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Sequence

import boto3

from engine import Engine, ExecutionContext
from models import ExecutionResult
from settings import Settings, load_settings

LOGGER = logging.getLogger(__name__)


def _mask_identifier(value: str) -> str:
    if not value:
        return "***"
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest()[:8]
    return f"{value[:2]}***{digest}"


def _build_execution_context(settings: Settings) -> ExecutionContext:
    """Create an execution context that captures schedule metadata."""
    return ExecutionContext(
        account_id=settings.account_id,
        region=settings.aws_region,
        invoked_at=datetime.now(timezone.utc),
        schedule_arn=settings.schedule_arn,
    )


def _extract_includes(event: Dict[str, Any]) -> Optional[Sequence[str]]:
    includes = event.get("includes") if isinstance(event, dict) else None
    if includes is None:
        return None
    if isinstance(includes, str):
        items = [item.strip().upper() for item in includes.split(",") if item.strip()]
        return items or None
    if isinstance(includes, list):
        items = [str(item).strip().upper() for item in includes if str(item).strip()]
        return items or None
    return None


def _build_clients(settings: Settings) -> Dict[str, Any]:
    """Instantiate AWS clients required by the engine and remediation flows."""
    client_kwargs = {"region_name": settings.aws_region}
    clients: Dict[str, Any] = {
        "iam": boto3.client("iam", **client_kwargs),
        "cloudtrail": boto3.client("cloudtrail", **client_kwargs),
        "logs": boto3.client("logs", **client_kwargs),
        "ec2": boto3.client("ec2", **client_kwargs),
        "s3": boto3.client("s3control", **client_kwargs),
        "cloudwatch": boto3.client("cloudwatch", **client_kwargs),
    }
    # Provide alias for callers expecting explicit s3control key.
    clients["s3control"] = clients["s3"]
    return clients


def _summarize(result: ExecutionResult) -> Dict[str, Any]:
    summary = result.summary
    return {
        "score": result.score.weighted,
        "total": result.score.total,
        "pass": summary.PASS,
        "fail": summary.FAIL,
        "warn": summary.WARN,
    }


def lambda_handler(event: Dict[str, Any], _: Any) -> Dict[str, Any]:
    """
    Lambda handler tying together configuration, engine execution, and persistence.

    The event is currently ignored but retained for future EventBridge enrichment.
    """
    try:
        settings = load_settings()
        clients = _build_clients(settings)
        engine = Engine(settings=settings)
        context = _build_execution_context(settings)

        includes = _extract_includes(event)
        result = engine.run_all_checks(context=context, clients=clients, includes=includes)
        engine.persist_result(result)
        reports = engine.publish_reports(result)

        summary = _summarize(result)
        LOGGER.info(
            "Mini-CSPM completed account=%s score=%s pass=%s fail=%s warn=%s findings=%s",
            _mask_identifier(result.account_id),
            summary["score"],
            summary["pass"],
            summary["fail"],
            summary["warn"],
            len(result.findings),
        )
        csv_report = reports.get("csv", {})
        if csv_report.get("url"):
            LOGGER.info("CSV report presigned URL: %s", csv_report["url"])

        return {
            "statusCode": 200,
            "body": {
                "account_id": result.account_id,
                "region": result.region,
                "timestamp": result.timestamp.isoformat(),
                "summary": summary,
                "reports": reports,
            },
        }
    except Exception as exc:  # pragma: no cover - defensive logging
        LOGGER.error("Mini-CSPM execution failed: %s", exc)
        LOGGER.debug("Mini-CSPM failure detail", exc_info=exc)
        return {"statusCode": 500, "body": {"error": str(exc)}}
