"""Registry of CIS control modules by benchmark version."""

from __future__ import annotations

import importlib
from typing import Dict, List

_MODULE_NAMES: List[str] = [
    "checks.cis_1_1_root_mfa",
    "checks.cis_1_2_no_root_keys",
    "checks.cis_1_3_root_access_key_rotated",
    "checks.cis_1_4_unused_credentials_disabled",
    "checks.cis_1_5_password_policy",
    "checks.cis_1_6_immediate_password_policy",
    "checks.cis_1_7_root_hardware_mfa",
    "checks.cis_1_8_vpc_flow_logs",
    "checks.cis_1_9_password_policy_expiry",
    "checks.cis_1_10_no_inline_policies_root",
    "checks.cis_1_11_no_admin_privilege_escalation",
    "checks.cis_1_12_awsmfa_console",
    "checks.cis_1_13_credential_report",
    "checks.cis_1_14_iam_access_analyzer",
    "checks.cis_1_15_no_root_access_keys",
    "checks.cis_1_16_securityhub_enabled",
    "checks.cis_1_17_waf_enabled",
    "checks.cis_1_18_guardduty_enabled",
    "checks.cis_1_19_cloudtrail_enabled",
    "checks.cis_1_20_iam_user_rotation",
    "checks.cis_1_21_kms_rotations",
    "checks.cis_1_22_mfa_console_users",
    "checks.cis_2_1_cloudtrail_all_regions",
    "checks.cis_2_2_cloudtrail_log_validation",
    "checks.cis_2_3_cloudtrail_encrypted_kms",
    "checks.cis_2_4_cloudtrail_bucket_logging",
    "checks.cis_2_5_s3_bucket_encryption",
    "checks.cis_3_1_unauth_api_metric_filter",
    "checks.cis_3_2_cloudwatch_alarm_root",
    "checks.cis_4_1_sg_no_0_0_0_0_22_3389",
    "checks.cis_5_1_s3_account_pab_on",
]


def _load_modules():
    modules = []
    for name in _MODULE_NAMES:
        modules.append(importlib.import_module(name))
    return modules


def _build_registry() -> Dict[str, Dict[str, object]]:
    registry: Dict[str, Dict[str, object]] = {}
    for module in _load_modules():
        meta = getattr(module, "META", {})
        cis_section = meta.get("cis")
        versions = meta.get("version", [])
        if not cis_section or not versions:
            continue
        control_id = meta.get("control_id", f"CIS-{cis_section}")
        for version in versions:
            registry.setdefault(version, {})[control_id] = module
    return registry


CONTROL_REGISTRY = _build_registry()
MODULE_NAMES = _MODULE_NAMES
