"""Environment variable loader for the Lambda runtime."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Mapping, Optional


def _to_bool(value: str | bool | int) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _require(env: Mapping[str, str], key: str) -> str:
    value = env.get(key)
    if value is None or value == "":
        raise KeyError(key)
    return value


@dataclass
class Settings:
    table_name: str
    report_bucket: str
    enable_pdf: bool = False
    enable_html: bool = False
    auto_remediate: int = 0
    csv_prefix: str = "reports/"
    html_prefix: str = "reports/"
    pdf_prefix: str = "reports/"
    fail_on: str = "HIGH"
    schedule_expression: str = "rate(24 hours)"
    schedule_arn: Optional[str] = None
    account_id: Optional[str] = None
    aws_region: str = field(default_factory=lambda: os.getenv("AWS_REGION", "us-east-1"))
    max_check_workers: int = 4
    check_timeout_seconds: int = 60
    max_concurrency: int = 10
    api_backoff: float = 1.0
    retain_days_s3: int = 365
    retain_days_ddb: int = 365
    unauth_mode: str = "logs"
    unauth_window_days: int = 7
    unauth_exclude_services: str = ""
    unauth_result_threshold: int = 0
    score_weight_pass: int = 10
    score_weight_warn: int = 5
    score_weight_fail: int = 0
    enable_presigned_urls: bool = True
    presign_ttl_seconds: int = 6 * 60 * 60
    wkhtmltopdf_path: Optional[str] = None
    remediation_apply_env_enabled: bool = False
    remediation_apply_parameter: Optional[str] = None
    score_threshold: int = 80
    event_bus_name: Optional[str] = None
    event_detail_type: str = "MiniCSPM.Alert"
    event_source: str = "mini-cspm"
    cis_version: str = "v1_5"
    export_to_security_hub: bool = False
    product_arn: Optional[str] = None
    _ALLOWED_FAIL_ON = {"NONE", "LOW", "MEDIUM", "HIGH"}
    _ALLOWED_CIS_VERSIONS = {"v1_5", "v5_0"}

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        env = env or os.environ
        try:
            return cls(
                table_name=_require(env, "TABLE_NAME"),
                report_bucket=_require(env, "REPORT_BUCKET"),
                enable_pdf=_to_bool(env.get("ENABLE_PDF", "false")),
                enable_html=_to_bool(env.get("ENABLE_HTML", "false")),
                auto_remediate=int(env.get("AUTO_REMEDIATE", "0")),
                csv_prefix=env.get("CSV_PREFIX", "reports/"),
                html_prefix=env.get("HTML_PREFIX", "reports/"),
                pdf_prefix=env.get("PDF_PREFIX", "reports/"),
                fail_on=env.get("FAIL_ON", "HIGH"),
                schedule_expression=env.get("SCHEDULE_EXPRESSION", "rate(24 hours)"),
                schedule_arn=env.get("SCHEDULE_ARN"),
                account_id=env.get("ACCOUNT_ID"),
                aws_region=env.get("AWS_REGION", os.getenv("AWS_REGION", "us-east-1")),
                max_check_workers=int(env.get("MAX_CHECK_WORKERS", "4")),
                check_timeout_seconds=int(env.get("CHECK_TIMEOUT_SECONDS", "60")),
                score_weight_pass=int(env.get("SCORE_WEIGHT_PASS", "10")),
                score_weight_warn=int(env.get("SCORE_WEIGHT_WARN", "5")),
                score_weight_fail=int(env.get("SCORE_WEIGHT_FAIL", "0")),
                enable_presigned_urls=_to_bool(env.get("ENABLE_PRESIGNED_URLS", "true")),
                presign_ttl_seconds=int(env.get("PRESIGN_TTL_SECONDS", str(6 * 60 * 60))),
                wkhtmltopdf_path=env.get("WKHTMLTOPDF_PATH"),
                remediation_apply_env_enabled=_to_bool(env.get("AUTO_REMEDIATE_APPLY", "false")),
                remediation_apply_parameter=env.get("REMEDIATION_APPLY_PARAMETER"),
                score_threshold=int(env.get("SCORE_THRESHOLD", "80")),
                event_bus_name=env.get("EVENT_BUS_NAME"),
                event_detail_type=env.get("EVENT_DETAIL_TYPE", "MiniCSPM.Alert"),
                event_source=env.get("EVENT_SOURCE", "mini-cspm"),
                cis_version=env.get("CIS_VERSION", "v1_5"),
                export_to_security_hub=_to_bool(env.get("EXPORT_TO_SECURITY_HUB", "false")),
                product_arn=env.get("PRODUCT_ARN"),
                unauth_mode=env.get("UNAUTH_MODE", "logs"),
                unauth_window_days=int(env.get("UNAUTH_WINDOW_DAYS", "7")),
                unauth_exclude_services=env.get("UNAUTH_EXCLUDE_SERVICES", ""),
                unauth_result_threshold=int(env.get("UNAUTH_RESULT_THRESHOLD", "0")),
                max_concurrency=int(env.get("MAX_CONCURRENCY", "10")),
                api_backoff=float(env.get("API_BACKOFF", "1.0")),
                retain_days_s3=int(env.get("RETAIN_DAYS_S3", "365")),
                retain_days_ddb=int(env.get("RETAIN_DAYS_DDB", "365")),
            )
        except KeyError as exc:
            raise RuntimeError(f"Missing required configuration: {exc.args[0]}") from exc

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "Settings":
        env = {key: str(value) for key, value in data.items()}
        return cls.from_env(env)

    def __post_init__(self) -> None:
        self.fail_on = self.fail_on.upper()
        if self.fail_on not in self._ALLOWED_FAIL_ON:
            raise ValueError(f"FAIL_ON must be one of {sorted(self._ALLOWED_FAIL_ON)}")
        if self.auto_remediate not in {0, 1, 2}:
            raise ValueError("AUTO_REMEDIATE must be 0, 1, or 2")
        if self.max_check_workers < 1:
            raise ValueError("MAX_CHECK_WORKERS must be >= 1")
        if self.check_timeout_seconds <= 0:
            raise ValueError("CHECK_TIMEOUT_SECONDS must be positive")
        if self.score_weight_pass <= 0:
            raise ValueError("SCORE_WEIGHT_PASS must be positive")
        if self.score_weight_warn < 0 or self.score_weight_fail < 0:
            raise ValueError("SCORE_WEIGHT_WARN and SCORE_WEIGHT_FAIL must be >= 0")
        if not (0 < self.score_threshold <= 100):
            raise ValueError("SCORE_THRESHOLD must be between 1 and 100")
        if self.cis_version not in self._ALLOWED_CIS_VERSIONS:
            raise ValueError(f"CIS_VERSION must be one of {sorted(self._ALLOWED_CIS_VERSIONS)}")
        if self.export_to_security_hub and not self.product_arn:
            if self.account_id and self.aws_region:
                self.product_arn = f"arn:aws:securityhub:{self.aws_region}:{self.account_id}:product/{self.account_id}/default"
            else:
                raise ValueError("PRODUCT_ARN must be provided when EXPORT_TO_SECURITY_HUB is true")
        if not self.table_name.strip():
            raise ValueError("TABLE_NAME cannot be blank")
        if self.unauth_mode not in {"logs", "lake"}:
            raise ValueError("UNAUTH_MODE must be 'logs' or 'lake'")
        if self.api_backoff <= 0:
            raise ValueError("API_BACKOFF must be positive")
        if self.max_concurrency < 1:
            raise ValueError("MAX_CONCURRENCY must be >= 1")
        if self.retain_days_s3 <= 0:
            raise ValueError("RETAIN_DAYS_S3 must be positive")
        if self.retain_days_ddb <= 0:
            raise ValueError("RETAIN_DAYS_DDB must be positive")
        if not self.report_bucket.strip():
            raise ValueError("REPORT_BUCKET cannot be blank")


def load_settings() -> Settings:
    """Load settings from environment variables."""
    return Settings.from_env()
