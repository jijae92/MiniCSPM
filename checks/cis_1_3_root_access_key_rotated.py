"""CIS 1.3 placeholder."""

from __future__ import annotations

from typing import Any, Dict, List

from settings import Settings


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:  # pragma: no cover - TODO implement
    """TODO: Implement cis_1_3_root_access_key_rotated check.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_password
    """
    raise NotImplementedError("CIS control 1.3 not yet implemented")
