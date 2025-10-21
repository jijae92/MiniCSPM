"""CIS 1.9 placeholder."""

from __future__ import annotations

from typing import Any, Dict, List

from settings import Settings


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:  # pragma: no cover - TODO implement
    """TODO: Implement cis_1_9_password_policy_expiry check.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html
    """
    raise NotImplementedError("CIS control 1.9 not yet implemented")
