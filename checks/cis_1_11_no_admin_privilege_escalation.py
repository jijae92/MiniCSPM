"""CIS 1.11 placeholder."""

from __future__ import annotations

from typing import Any, Dict, List

from settings import Settings

META = {
    "cis": "1.11",
    "version": ['v1_5']
}


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:  # pragma: no cover - TODO implement
    """TODO: Implement cis_1_11_no_admin_privilege_escalation check.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials
    """
    raise NotImplementedError("CIS control 1.11 not yet implemented")
