"""CIS 1.13 placeholder."""

from __future__ import annotations

from typing import Any, Dict, List

from settings import Settings

META = {
    "cis": "1.13",
    "version": ['v1_5']
}


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:  # pragma: no cover - TODO implement
    """TODO: Implement cis_1_13_credential_report check.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/credential-reports.html
    """
    raise NotImplementedError("CIS control 1.13 not yet implemented")
