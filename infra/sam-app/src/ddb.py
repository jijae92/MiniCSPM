"""Thin DynamoDB wrapper for execution result persistence."""

from __future__ import annotations

from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key

from models import ExecutionResult
from settings import Settings, load_settings

_DDB_RESOURCE = boto3.resource("dynamodb")


def _table(settings: Settings):
    return _DDB_RESOURCE.Table(settings.table_name)


def clear_latest_flag(account_id: str) -> None:
    """Reset the latest flag for existing execution records in the account partition."""
    if not account_id:
        return

    settings = load_settings()
    table = _table(settings)
    last_evaluated_key = None

    try:
        while True:
            query_kwargs: Dict[str, Any] = {
                "KeyConditionExpression": Key("account_id").eq(account_id),
                "ProjectionExpression": "account_id, ts, latest",
            }
            if last_evaluated_key:
                query_kwargs["ExclusiveStartKey"] = last_evaluated_key
            response = table.query(**query_kwargs)
            items = response.get("Items", [])
            for item in items:
                if item.get("latest"):
                    table.update_item(
                        Key={"account_id": item["account_id"], "ts": item["ts"]},
                        UpdateExpression="SET latest = :flag",
                        ExpressionAttributeValues={":flag": False},
                    )
            last_evaluated_key = response.get("LastEvaluatedKey")
            if not last_evaluated_key:
                break
    except ClientError as error:  # pragma: no cover - network failure
        raise RuntimeError(f"Failed to clear latest flag in DynamoDB: {error}") from error


def put_execution_result(result: ExecutionResult) -> None:
    """Persist an execution result using account/timestamp composite key."""
    settings = load_settings()
    item: Dict[str, Any] = {
        "account_id": result.account_id,
        "ts": result.timestamp.isoformat(),
        "result": result.to_dict(),
        "latest": True,
    }
    try:
        _table(settings).put_item(Item=item)
    except ClientError as error:
        # TODO: route to DLQ/metrics once CloudWatch alarms are in place.
        raise RuntimeError(f"Failed to write result to DynamoDB: {error}") from error


def get_latest_execution(account_id: str) -> Dict[str, Any]:
    """Fetch the latest execution result for local testing or remediation follow-up."""
    settings = load_settings()
    response = _table(settings).query(
        KeyConditionExpression=Key("account_id").eq(account_id),
        ScanIndexForward=False,
        Limit=1,
    )
    items = response.get("Items", [])
    return items[0] if items else {}
