"""CIS 1.12 placeholder."""

from __future__ import annotations

from typing import Any, Dict, List

from settings import Settings

META = {
    "cis": "1.12",
    "version": ['v1_5']
}


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:  # pragma: no cover - TODO implement
    """TODO: Implement cis_1_12_awsmfa_console check.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html
    """
    raise NotImplementedError("CIS control 1.12 not yet implemented")
