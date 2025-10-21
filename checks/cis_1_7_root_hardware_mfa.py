"""CIS 1.7 placeholder."""

from __future__ import annotations

from typing import Any, Dict, List

from settings import Settings

META = {
    "cis": "1.7",
    "version": ['v1_5']
}


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:  # pragma: no cover - TODO implement
    """TODO: Implement cis_1_7_root_hardware_mfa check.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_authenticate_mfa-enable.html
    """
    raise NotImplementedError("CIS control 1.7 not yet implemented")
