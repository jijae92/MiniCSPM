"""Auto-remediation framework for Mini-CSPM findings."""

from __future__ import annotations

import logging
import hashlib
from typing import Callable, Dict, Iterable, Optional

from models import Finding, RemediationResult
from settings import Settings

logger = logging.getLogger(__name__)


def _mask(value: str) -> str:
    if not value:
        return "***"
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest()[:8]
    return f"{value[:2]}***{digest}"

RemediationHandler = Callable[[Finding, Settings, Dict[str, object], bool], str]

SAFE_ACTIONS = {
    "enable_account_pab",
    "set_strong_password_policy",
    "revoke_sg_open_admin_ports",
    "create_metric_filter_alarm_unauth",
}

_REGISTRY: Dict[str, RemediationHandler] = {}


def register(action_name: str) -> Callable[[RemediationHandler], RemediationHandler]:
    """Decorator to register remediation handlers by action name."""

    def _inner(func: RemediationHandler) -> RemediationHandler:
        _REGISTRY[action_name] = func
        return func

    return _inner


def list_actions() -> Iterable[str]:
    """Return all registered remediation action names."""
    return _REGISTRY.keys()


def remediate(
    action: str,
    finding: Finding,
    settings: Settings,
    clients: Dict[str, object],
    allow_apply: bool = False,
) -> RemediationResult:
    """
    Execute an auto-remediation flow according to the configured mode.

    Modes:
    - 0: skip and log intent.
    - 1: dry-run, surface plan only.
    - 2: execute safe actions, otherwise fall back to dry-run for sensitive/unknown actions.
    """
    mode = settings.auto_remediate
    handler = _REGISTRY.get(action)
    if handler is None:
        message = f"action {action} not registered"
        logger.info("Skipping remediation for %s: %s", action, message)
        return RemediationResult(action=action, mode="SKIP", applied=False, message=message, error="not_registered")

    if mode <= 0:
        message = "auto-remediation disabled"
        logger.info("Auto-remediation disabled; skipping %s", action)
        return RemediationResult(action=action, mode="SKIP", applied=False, message=message)

    sensitive = _is_sensitive_action(action)
    should_apply = mode >= 2 and action in SAFE_ACTIONS and not sensitive and allow_apply
    execution_mode = "APPLY" if should_apply else "DRY_RUN"

    try:
        message = handler(finding, settings, clients, should_apply)
        logger.info(
            "Remediation %s for finding %s executed in mode %s",
            action,
            _mask(finding.id),
            execution_mode,
        )
        return RemediationResult(action=action, mode=execution_mode, applied=should_apply, message=message)
    except Exception as exc:  # pragma: no cover - defensive guard rails
        logger.error("Remediation %s failed for finding %s: %s", action, _mask(finding.id), exc)
        logger.debug("Remediation failure detail", exc_info=exc)
        return RemediationResult(
            action=action,
            mode="FAILED",
            applied=False,
            message=f"failed: {exc}",
            error=str(exc),
        )


def _is_sensitive_action(action: str) -> bool:
    """Flag CloudTrail/KMS related actions for dry-run protection."""
    lowered = action.lower()
    return "cloudtrail" in lowered or "kms" in lowered


def _account_id(finding: Finding, settings: Settings) -> str:
    return (finding.resource_ids[0] if finding.resource_ids else None) or settings.account_id or "unknown"


@register("enable_account_pab")
def _enable_account_pab(
    finding: Finding,
    settings: Settings,
    clients: Dict[str, object],
    apply_changes: bool,
) -> str:
    account_id = _account_id(finding, settings)
    s3_client = clients.get("s3") or clients.get("s3control")
    if s3_client is None:
        raise RuntimeError("s3 client unavailable")

    config = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }
    if apply_changes:
        s3_client.put_public_access_block(
            AccountId=account_id,
            PublicAccessBlockConfiguration=config,
        )
        return f"Enabled account-level S3 public access block for {_mask(account_id)}"
    return f"Would enable account-level S3 public access block for {_mask(account_id)}"


@register("set_strong_password_policy")
def _set_strong_password_policy(
    finding: Finding,
    settings: Settings,
    clients: Dict[str, object],
    apply_changes: bool,
) -> str:
    iam_client = clients.get("iam")
    if iam_client is None:
        raise RuntimeError("iam client unavailable")

    policy = {
        "MinimumPasswordLength": 14,
        "RequireSymbols": True,
        "RequireNumbers": True,
        "RequireUppercaseCharacters": True,
        "RequireLowercaseCharacters": True,
        "MaxPasswordAge": 90,
        "PasswordReusePrevention": 24,
    }
    if apply_changes:
        iam_client.update_account_password_policy(**policy)
        return "Applied strong account password policy"
    return "Would apply strong account password policy"


@register("revoke_sg_open_admin_ports")
def _revoke_sg_open_admin_ports(
    finding: Finding,
    settings: Settings,
    clients: Dict[str, object],
    apply_changes: bool,
) -> str:
    ec2_client = clients.get("ec2")
    if ec2_client is None:
        raise RuntimeError("ec2 client unavailable")

    targets = finding.evidence.get("security_groups", finding.resource_ids)
    ports = finding.evidence.get("ports", [22, 3389])
    if apply_changes:
        for sg_id in targets:
            for port in ports:
                ec2_client.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[
                        {
                            "IpProtocol": "tcp",
                            "FromPort": port,
                            "ToPort": port,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                )
        masked_targets = ', '.join(_mask(t) for t in targets)
        return f"Revoked open admin ports {ports} for {masked_targets}"
    masked_targets = ', '.join(_mask(t) for t in targets)
    return f"Would revoke open admin ports {ports} for {masked_targets}"


@register("create_metric_filter_alarm_unauth")
def _create_metric_filter_alarm_unauth(
    finding: Finding,
    settings: Settings,
    clients: Dict[str, object],
    apply_changes: bool,
) -> str:
    logs_client = clients.get("logs")
    cloudwatch_client = clients.get("cloudwatch")
    if logs_client is None or cloudwatch_client is None:
        raise RuntimeError("logs/cloudwatch clients unavailable")

    metric_name = "UnauthorizedApiCalls"
    filter_name = f"auto-{metric_name}"
    log_group = settings.account_id or "unknown-account"
    alarm_name = f"MiniCSPM-{metric_name}"

    if apply_changes:
        logs_client.put_metric_filter(
            logGroupName=log_group,
            filterName=filter_name,
            filterPattern='{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }',
            metricTransformations=[
                {"metricName": metric_name, "metricNamespace": "MiniCSPM", "metricValue": "1"},
            ],
        )
        cloudwatch_client.put_metric_alarm(
            AlarmName=alarm_name,
            MetricName=metric_name,
            Namespace="MiniCSPM",
            Statistic="Sum",
            Period=300,
            EvaluationPeriods=1,
            Threshold=1,
            ComparisonOperator="GreaterThanOrEqualToThreshold",
            AlarmDescription="Automated alarm for unauthorized API activity",
            ActionsEnabled=False,
        )
        return f"Created unauthorized API metric filter and alarm {alarm_name}"

    return f"Would create unauthorized API metric filter and alarm {alarm_name}"
