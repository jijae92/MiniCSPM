"""Core orchestration logic for running CIS checks and persisting results."""

from __future__ import annotations

import csv
import importlib
import io
import json
import logging
import hashlib
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from botocore.exceptions import ClientError

from checks import CHECK_REGISTRY
from models import ExecutionContext, ExecutionResult, Finding, Score, Summary
from settings import Settings
import ddb
import html_report
import pdf_report
import remediation
import boto3

logger = logging.getLogger(__name__)


def _mask_identifier(value: str) -> str:
    if not value:
        return "***"
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest()[:8]
    return f"{value[:2]}***{digest}"


DEFAULT_CHECK_IDS = [
    "CIS-1.1",
    "CIS-1.2",
    "CIS-1.5",
    "CIS-1.22",
    "CIS-2.1",
    "CIS-2.2",
    "CIS-2.3",
    "CIS-3.1",
    "CIS-4.1",
    "CIS-5.1",
]


@dataclass
class CheckOutcome:
    """Container for per-check execution metadata."""

    name: str
    findings: List[Finding]
    status: str


class Engine:
    """Coordinate check execution, scoring, report generation, and persistence."""

    def __init__(
        self,
        settings: Settings,
        *,
        s3_client: Optional[object] = None,
        events_client: Optional[object] = None,
        ssm_client: Optional[object] = None,
        executor_cls=ThreadPoolExecutor,
    ) -> None:
        self.settings = settings
        self._check_registry = dict(CHECK_REGISTRY)
        self._module_cache: Dict[str, object] = {}
        for check_id, runner in self._check_registry.items():
            module_name = runner.__module__
            self._module_cache[check_id] = importlib.import_module(module_name)
        if s3_client is None:
            self._s3_client = boto3.client("s3")
        else:
            self._s3_client = s3_client
        if events_client is None:
            self._events_client = boto3.client("events")
        else:
            self._events_client = events_client
        if ssm_client is None:
            self._ssm_client = boto3.client("ssm")
        else:
            self._ssm_client = ssm_client
        self._apply_guard_result: Optional[bool] = None
        self._executor_cls = executor_cls

    def execute(
        self,
        context: ExecutionContext,
        clients: Optional[Dict[str, object]] = None,
    ) -> Dict[str, object]:
        """
        Run every check, persist the result set, publish reports, and return JSON output.
        """
        result = self.run_all_checks(context=context, clients=clients)
        self.persist_result(result)
        reports = self.publish_reports(result)
        payload = result.to_dict()
        payload["reports"] = reports
        return payload

    def execute(
        self,
        context: ExecutionContext,
        clients: Optional[Dict[str, object]] = None,
        includes: Optional[Sequence[str]] = None,
    ) -> Dict[str, object]:
        """
        Run every check, persist the result set, publish reports, and return JSON output.
        """
        result = self.run_all_checks(context=context, clients=clients, includes=includes)
        self.persist_result(result)
        reports = self.publish_reports(result)
        payload = result.to_dict()
        payload["reports"] = reports
        return payload

    def run_all_checks(
        self,
        context: ExecutionContext,
        clients: Optional[Dict[str, object]] = None,
        includes: Optional[Sequence[str]] = None,
    ) -> ExecutionResult:
        """Execute every check module and build an ExecutionResult."""
        client_pool = clients or self._build_clients()
        check_ids = self._resolve_check_ids(includes)
        outcomes = self._execute_checks(check_ids=check_ids, context=context, clients=client_pool)
        findings: List[Finding] = [finding for outcome in outcomes for finding in outcome.findings]
        if self.settings.auto_remediate > 0:
            self._run_remediations(findings, client_pool)

        score = self._score_outcomes(outcomes)
        summary = self._summarize(findings)

        return ExecutionResult(
            account_id=context.account_id or self.settings.account_id or "000000000000",
            region=context.region or self.settings.aws_region,
            timestamp=datetime.now(timezone.utc),
            findings=findings,
            score=score,
            summary=summary,
        )

    def persist_result(self, result: ExecutionResult) -> None:
        """Persist the execution outcome in DynamoDB and update latest flags."""
        if result.account_id:
            ddb.clear_latest_flag(account_id=result.account_id)
        ddb.put_execution_result(result)

    def publish_reports(self, result: ExecutionResult) -> Dict[str, Optional[str]]:
        """Generate the CSV report, upload to S3, and optionally emit a presigned URL."""
        key, presigned_url = self._write_csv_report(result)
        if presigned_url:
            logger.info("Generated presigned CSV URL for account %s", _mask_identifier(result.account_id))
        if self.settings.enable_html:
            html_report.write_html(result=result, settings=self.settings)
        if self.settings.enable_pdf:
            pdf_report.write_pdf(result=result, settings=self.settings)
        self._maybe_emit_alert(result)
        if self._should_fail(result):
            raise RuntimeError(f"Failing execution due to severity threshold {self.settings.fail_on}")
        return {
            "csv": {
                "bucket": self.settings.report_bucket,
                "key": key,
                "url": presigned_url,
            }
        }

    def _resolve_check_ids(self, includes: Optional[Sequence[str]]) -> List[str]:
        if includes:
            resolved: List[str] = []
            for item in includes:
                check_id = item.strip().upper()
                if check_id in self._check_registry:
                    resolved.append(check_id)
                else:
                    logger.warning("Ignoring unknown check id: %s", item)
            if resolved:
                return resolved
            logger.warning("No valid check ids resolved from includes; falling back to defaults")
        return [check_id for check_id in DEFAULT_CHECK_IDS if check_id in self._check_registry]

    def _execute_checks(
        self,
        check_ids: Sequence[str],
        context: ExecutionContext,
        clients: Dict[str, object],
    ) -> List[CheckOutcome]:
        workers = max(1, min(self.settings.max_check_workers, len(check_ids)))
        outcomes: List[CheckOutcome] = []

        if workers == 1:
            for check_id in check_ids:
                outcomes.append(self._run_check(check_id, context, clients))
            return outcomes

        with self._executor_cls(max_workers=workers) as executor:
            futures = {
                executor.submit(self._run_check, check_id, context, clients): check_id for check_id in check_ids
            }
            for future, check_id in futures.items():
                try:
                    outcomes.append(future.result(timeout=self.settings.check_timeout_seconds))
                except FuturesTimeoutError:
                    logger.warning(
                        "Check %s timed out after %s seconds",
                        check_id,
                        self.settings.check_timeout_seconds,
                    )
                    outcomes.append(self._timeout_outcome(check_id, context))
                except Exception as exc:  # pragma: no cover - already handled in _run_check
                    logger.error("Unexpected failure from check %s: %s", check_id, exc)
                    logger.debug("Check execution error detail", exc_info=exc)
                    outcomes.append(self._error_outcome(check_id, context, exc))

        return outcomes

    def _run_check(
        self,
        check_id: str,
        context: ExecutionContext,
        clients: Dict[str, object],
    ) -> CheckOutcome:
        runner = self._check_registry[check_id]
        module = self._module_cache[check_id]
        try:
            raw = runner(settings=self.settings, clients=clients)
        except Exception as exc:  # pragma: no cover - reported via WARN finding
            logger.error("Check %s raised an exception: %s", check_id, exc)
            logger.debug("Check exception detail", exc_info=exc)
            return self._error_outcome(check_id, context, exc)

        findings = [Finding.from_dict(item) for item in raw]
        status = self._aggregate_status(findings)
        return CheckOutcome(name=check_id, findings=findings, status=status)

    def _error_outcome(self, check_id: str, context: ExecutionContext, exc: Exception) -> CheckOutcome:
        module = self._module_cache.get(check_id)
        finding = self._fallback_finding(check_id, module, context, f"exception: {exc}")
        return CheckOutcome(name=check_id, findings=[finding], status="WARN")

    def _timeout_outcome(self, check_id: str, context: ExecutionContext) -> CheckOutcome:
        module = self._module_cache.get(check_id)
        finding = self._fallback_finding(check_id, module, context, "timeout")
        return CheckOutcome(name=check_id, findings=[finding], status="WARN")

    def _fallback_finding(self, check_id: str, module, context: ExecutionContext, note: str) -> Finding:
        module_doc = getattr(module, "__doc__", None) if module else None
        title = (module_doc or check_id).strip().splitlines()[0]
        control_id = getattr(module, "CONTROL_ID", check_id)
        return Finding(
            id=control_id,
            title=title,
            cis=getattr(module, "CIS_SECTION", control_id.replace("CIS-", "")),
            service=getattr(module, "SERVICE", "unknown"),
            severity="MEDIUM",
            status="WARN",
            resource_ids=[context.account_id or self.settings.account_id or "unknown"],
            evidence={"note": note},
            remediable=False,
            remediation_action="",
            references=[],
            checked_at=datetime.now(timezone.utc),
        )

    def _aggregate_status(self, findings: Sequence[Finding]) -> str:
        statuses = {finding.status for finding in findings}
        if "FAIL" in statuses:
            return "FAIL"
        if "WARN" in statuses:
            return "WARN"
        return "PASS"

    def _run_remediations(self, findings: Sequence[Finding], clients: Dict[str, object]) -> None:
        """Run sequential remediations for failing, remediable findings."""
        allow_apply = self._allow_apply()
        for finding in findings:
            if finding.status != "FAIL":
                continue
            if not finding.remediable:
                continue
            action = getattr(finding, "remediation_action", "") or ""
            if not action:
                continue
            result = remediation.remediate(
                action=action,
                finding=finding,
                settings=self.settings,
                clients=clients,
                allow_apply=allow_apply,
            )
            if result:
                remediation_log = finding.evidence.setdefault("remediations", [])
                remediation_log.append(result.to_dict())

    def _allow_apply(self) -> bool:
        if self._apply_guard_result is not None:
            return self._apply_guard_result
        if self.settings.auto_remediate < 2:
            self._apply_guard_result = False
            return False
        if not self.settings.remediation_apply_env_enabled:
            logger.info("AUTO_REMEDIATE_APPLY guard disabled; running in dry-run mode")
            self._apply_guard_result = False
            return False
        if not self.settings.remediation_apply_parameter:
            logger.warning("Remediation apply parameter not configured; defaulting to dry-run")
            self._apply_guard_result = False
            return False
        param_name = self.settings.remediation_apply_parameter
        try:
            response = self._ssm_client.get_parameter(Name=param_name)
            value = response.get("Parameter", {}).get("Value", "")
        except ClientError as exc:
            error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "error")
            logger.error(
                "Failed to read remediation guard parameter %s: %s",
                _mask_identifier(param_name),
                error_code,
            )
            logger.debug("SSM get_parameter failure", exc_info=exc)
            self._apply_guard_result = False
            return False
        allowed = str(value).strip().lower() in {"1", "true", "yes", "on", "apply"}
        if not allowed:
            logger.info(
                "Remediation guard parameter %s disabled; running in dry-run mode",
                _mask_identifier(param_name),
            )
        self._apply_guard_result = allowed
        return allowed

    def _maybe_emit_alert(self, result: ExecutionResult) -> None:
        alert = self._build_alert_payload(result)
        if not alert:
            return
        if not self.settings.event_bus_name:
            logger.debug("Event bus name not configured; skipping alert emission")
            return
        try:
            self._events_client.put_events(
                Entries=[
                    {
                        "Source": self.settings.event_source,
                        "DetailType": self.settings.event_detail_type,
                        "EventBusName": self.settings.event_bus_name,
                        "Detail": json.dumps(alert),
                    }
                ]
            )
            logger.info(
                "Published alert to EventBridge bus %s (high_failures=%s, weighted=%s)",
                self.settings.event_bus_name,
                alert["metrics"]["high_failures"],
                alert["metrics"]["weighted_score"],
            )
        except Exception as exc:  # pragma: no cover - defensive logging only
            logger.warning("Failed to publish alert event: %s", exc)

    def _build_alert_payload(self, result: ExecutionResult) -> Optional[Dict[str, object]]:
        high_failures = sum(1 for f in result.findings if f.status == "FAIL" and f.severity == "HIGH")
        weighted = result.score.weighted
        if high_failures < 1 and weighted >= self.settings.score_threshold:
            return None
        return {
            "account_id": result.account_id,
            "region": result.region,
            "timestamp": result.timestamp.isoformat(),
            "metrics": {
                "high_failures": high_failures,
                "weighted_score": weighted,
                "total_findings": len(result.findings),
            },
            "thresholds": {
                "score_threshold": self.settings.score_threshold,
                "fail_on": self.settings.fail_on,
            },
        }

    def _score_outcomes(self, outcomes: Sequence[CheckOutcome]) -> Score:
        total_checks = len(outcomes)
        pass_weight = self.settings.score_weight_pass
        warn_weight = self.settings.score_weight_warn
        fail_weight = self.settings.score_weight_fail

        points = 0
        passed = 0
        failed = 0
        warned = 0

        weight_map = {"PASS": pass_weight, "WARN": warn_weight, "FAIL": fail_weight}
        for outcome in outcomes:
            status = outcome.status
            points += weight_map.get(status, 0)
            if status == "PASS":
                passed += 1
            elif status == "FAIL":
                failed += 1
            elif status == "WARN":
                warned += 1

        max_points = total_checks * pass_weight if total_checks else 0
        weighted = 0
        if max_points:
            weighted = round((points / max_points) * 100)

        return Score(total=total_checks, passed=passed, failed=failed, weighted=weighted, warned=warned)

    def _summarize(self, findings: Iterable[Finding]) -> Summary:
        summary = Summary()
        for finding in findings:
            if hasattr(summary, finding.severity):
                setattr(summary, finding.severity, getattr(summary, finding.severity) + 1)
            if hasattr(summary, finding.status):
                setattr(summary, finding.status, getattr(summary, finding.status) + 1)
        return summary

    def _write_csv_report(self, result: ExecutionResult) -> Tuple[str, Optional[str]]:
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            [
                "timestamp",
                "account_id",
                "control_id",
                "title",
                "severity",
                "status",
                "resource_ids",
                "notes",
            ]
        )
        timestamp_iso = result.timestamp.isoformat()
        for finding in result.findings:
            notes = json.dumps(finding.evidence, default=str) if finding.evidence else ""
            writer.writerow(
                [
                    timestamp_iso,
                    result.account_id,
                    finding.id,
                    finding.title,
                    finding.severity,
                    finding.status,
                    ",".join(finding.resource_ids),
                    notes,
                ]
            )

        key = self._build_csv_key(result)
        body = buffer.getvalue().encode("utf-8")
        self._s3_client.put_object(
            Bucket=self.settings.report_bucket,
            Key=key,
            Body=body,
            ContentType="text/csv",
        )

        presigned_url: Optional[str] = None
        if self.settings.enable_presigned_urls:
            try:
                presigned_url = self._s3_client.generate_presigned_url(
                    ClientMethod="get_object",
                    Params={"Bucket": self.settings.report_bucket, "Key": key},
                    ExpiresIn=self.settings.presign_ttl_seconds,
                )
            except Exception as exc:  # pragma: no cover - logging only
                logger.warning("Failed to create presigned URL for %s: %s", key, exc)

        logger.info(
            "CSV report stored at s3://%s/%s for account %s",
            self.settings.report_bucket,
            key,
            result.account_id,
        )

        return key, presigned_url

    def _build_csv_key(self, result: ExecutionResult) -> str:
        prefix = self.settings.csv_prefix or ""
        if prefix and not prefix.endswith("/"):
            prefix += "/"
        account_id = result.account_id or "unknown"
        timestamp_fragment = result.timestamp.strftime("%Y%m%dT%H%M%SZ")
        return f"{prefix}{account_id}/{timestamp_fragment}.csv"

    def _should_fail(self, result: ExecutionResult) -> bool:
        """Determine whether to fail the execution based on severity thresholds."""
        threshold = self.settings.fail_on.upper()
        if threshold == "NONE":
            return False
        if threshold == "HIGH" and result.summary.HIGH > 0:
            return True
        if threshold == "MEDIUM" and (result.summary.MEDIUM > 0 or result.summary.HIGH > 0):
            return True
        if threshold == "LOW" and (
            result.summary.LOW > 0 or result.summary.MEDIUM > 0 or result.summary.HIGH > 0
        ):
            return True
        return False

    def _build_clients(self) -> Dict[str, object]:
        import boto3

        return {
            "iam": boto3.client("iam"),
            "cloudtrail": boto3.client("cloudtrail"),
            "logs": boto3.client("logs"),
            "ec2": boto3.client("ec2"),
            "s3": boto3.client("s3control"),
        }
