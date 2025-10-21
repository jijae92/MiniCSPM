"""Developer CLI for running Mini-CSPM checks locally."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

ROOT = Path(__file__).resolve().parents[1]
CORE_PATH = ROOT / "infra" / "sam-app" / "src"
if str(CORE_PATH) not in sys.path:
    sys.path.insert(0, str(CORE_PATH))

from engine import Engine  # type: ignore  # noqa: E402
from models import ExecutionContext  # type: ignore  # noqa: E402
from settings import Settings, load_settings  # type: ignore  # noqa: E402

EXIT_SUCCESS = 0
EXIT_FAILURE = 2


def build_local_settings(auto_remediate: Optional[int] = None) -> Settings:
    """Create settings from env with sensible defaults for local runs."""
    defaults = {
        "TABLE_NAME": os.environ.get("TABLE_NAME", "MiniCspmResults"),
        "REPORT_BUCKET": os.environ.get("REPORT_BUCKET", "mini-cspm-local"),
        "ENABLE_PDF": os.environ.get("ENABLE_PDF", "false"),
        "ENABLE_HTML": os.environ.get("ENABLE_HTML", "false"),
        "CSV_PREFIX": os.environ.get("CSV_PREFIX", "reports/"),
        "HTML_PREFIX": os.environ.get("HTML_PREFIX", "reports/"),
        "PDF_PREFIX": os.environ.get("PDF_PREFIX", "reports/"),
        "FAIL_ON": os.environ.get("FAIL_ON", "HIGH"),
    }
    defaults["AUTO_REMEDIATE"] = str(auto_remediate) if auto_remediate is not None else os.environ.get(
        "AUTO_REMEDIATE", "0"
    )
    os.environ.update(defaults)
    return load_settings()


def _parse_includes(value: Optional[str]) -> Optional[Sequence[str]]:
    if value is None:
        return None
    items = [item.strip().upper() for item in value.split(",") if item.strip()]
    return items or None


def run_scan(
    output_path: Path,
    fmt: str,
    auto_remediate: Optional[int],
    includes: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Execute checks and render a local artifact."""
    settings = build_local_settings(auto_remediate=auto_remediate)
    engine = Engine(settings=settings)
    context = ExecutionContext(
        account_id=settings.account_id or "000000000000",
        region=settings.aws_region,
        invoked_at=datetime.now(timezone.utc),
    )
    result = engine.run_all_checks(context=context, includes=includes)
    result_dict = result.to_dict()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        output_path.write_text(json.dumps(result_dict, indent=2))
    elif fmt == "csv":
        _write_csv_local(result_dict, output_path)
    else:  # pragma: no cover
        raise ValueError(f"Unsupported format {fmt}")

    print(f"Wrote Mini-CSPM {fmt.upper()} report to {output_path}")
    return result_dict


def _write_csv_local(result: dict, path: Path) -> None:
    """Local helper mirroring csv_report.write_csv without S3 dependency."""
    findings = result.get("findings", [])
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
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
        )
        for finding in findings:
            writer.writerow(
                [
                    finding.get("id"),
                    finding.get("title"),
                    finding.get("cis"),
                    finding.get("service"),
                    finding.get("severity"),
                    finding.get("status"),
                    ";".join(finding.get("resource_ids", [])),
                    "yes" if finding.get("remediable") else "no",
                    finding.get("remediation_action") or "",
                    finding.get("checked_at"),
                ]
            )


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="minicspm.cli")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run all CIS checks locally")
    scan.add_argument("--format", "-f", choices=["csv", "json"], default="csv")
    scan.add_argument("--out", "-o", type=Path)
    scan.add_argument("--auto-remediate", type=int, choices=[0, 1, 2], dest="auto_remediate", default=None)
    scan.add_argument(
        "--includes",
        type=str,
        help="Comma-separated list of CIS control IDs (e.g. 'CIS-1.1,CIS-4.1')",
    )

    score = subparsers.add_parser("score", help="Summarize an execution result JSON file")
    score.add_argument("--from", dest="from_path", type=Path, required=True)

    findings = subparsers.add_parser("findings", help="Show failing findings from execution result JSON")
    findings.add_argument("--from", dest="from_path", type=Path, required=True)

    return parser.parse_args(list(argv))


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        if args.command == "scan":
            fmt = args.format
            output_path = args.out or Path(f"mini-cspm-report.{fmt}")
            includes = _parse_includes(getattr(args, "includes", None))
            run_scan(output_path=output_path, fmt=fmt, auto_remediate=args.auto_remediate, includes=includes)
        elif args.command == "score":
            _print_score(args.from_path)
        elif args.command == "findings":
            _print_failures(args.from_path)
        else:  # pragma: no cover
            raise ValueError(f"Unknown command {args.command}")
    except Exception as exc:  # pragma: no cover - top level guard
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    return EXIT_SUCCESS


def _load_result(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(path)
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _print_score(path: Path) -> None:
    result = _load_result(path)
    score = result.get("score", {})
    summary = result.get("summary", {})
    print("Mini-CSPM Score Summary")
    print("======================")
    print(f"Weighted Score : {score.get('weighted', 'n/a')}")
    print(f"Total Checks   : {score.get('total', 'n/a')}")
    print(f"Passed         : {score.get('passed', summary.get('PASS', 'n/a'))}")
    print(f"Failed         : {score.get('failed', summary.get('FAIL', 'n/a'))}")
    print(f"Warnings       : {score.get('warned', summary.get('WARN', 'n/a'))}")


def _print_failures(path: Path) -> None:
    result = _load_result(path)
    findings: Sequence[Dict[str, Any]] = result.get("findings", [])
    failures = [finding for finding in findings if finding.get("status") == "FAIL"]
    if not failures:
        print("No failing findings.")
        return

    headers = ["ID", "Title", "Severity", "Service", "Resources"]
    rows = [
        [
            fail.get("id", ""),
            fail.get("title", ""),
            fail.get("severity", ""),
            fail.get("service", ""),
            ", ".join(fail.get("resource_ids", [])),
        ]
        for fail in failures
    ]
    column_widths = [max(len(str(row[idx])) for row in ([headers] + rows)) for idx in range(len(headers))]

    def _format_row(values: Sequence[str]) -> str:
        return " | ".join(str(value).ljust(column_widths[idx]) for idx, value in enumerate(values))

    print(_format_row(headers))
    print("-+-".join("-" * width for width in column_widths))
    for row in rows:
        print(_format_row(row))


if __name__ == "__main__":
    sys.exit(main())
