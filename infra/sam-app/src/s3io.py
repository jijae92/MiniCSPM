"""S3 helpers for report archival and presigned URL creation."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Optional

import boto3
from botocore.exceptions import ClientError

from models import ExecutionResult
from settings import Settings, load_settings

_s3_client = boto3.client("s3")


def put_object(key: str, body: bytes, content_type: str) -> str:
    """Upload a report object and return the S3 key."""
    settings = load_settings()
    _s3_client.put_object(Bucket=settings.report_bucket, Key=key, Body=body, ContentType=content_type)
    return key


def presign(key: str, expires_in: int = int(timedelta(hours=6).total_seconds())) -> Optional[str]:
    """Create a presigned URL to share the generated report."""
    settings = load_settings()
    try:
        return _s3_client.generate_presigned_url(
            ClientMethod="get_object",
            Params={"Bucket": settings.report_bucket, "Key": key},
            ExpiresIn=expires_in,
        )
    except ClientError as exc:
        logging.warning("Failed to generate presigned URL for %s: %s", key, exc)
        return None


def build_report_key(prefix: str, result: ExecutionResult, extension: str) -> str:
    """Construct versioned report keys using account/timestamp."""
    ts = result.timestamp.strftime("%Y%m%dT%H%M%SZ")
    return f"{prefix.rstrip('/')}/{result.account_id}/{ts}.{extension.lstrip('.')}"
