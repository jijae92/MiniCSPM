"""CSV report generator for Mini-CSPM findings."""

from __future__ import annotations

import csv
import io

from models import ExecutionResult
from settings import Settings
import s3io


CSV_HEADER = [
    "finding_id",
    "title",
    "cis",
    "service",
    "severity",
    "status",
    "resource_ids",
    "remediable",
    "remediation_action",
    "checked_at",
]


def write_csv(result: ExecutionResult, settings: Settings) -> str:
    """Serialize findings into CSV and upload to S3."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(CSV_HEADER)
    for finding in result.findings:
        writer.writerow(
            [
                finding.id,
                finding.title,
                finding.cis,
                finding.service,
                finding.severity,
                finding.status,
                ";".join(finding.resource_ids),
                "yes" if finding.remediable else "no",
                finding.remediation_action or "",
                finding.checked_at.isoformat(),
            ]
        )

    key = s3io.build_report_key(settings.csv_prefix, result, "csv")
    s3io.put_object(key=key, body=buffer.getvalue().encode("utf-8"), content_type="text/csv")
    return key
