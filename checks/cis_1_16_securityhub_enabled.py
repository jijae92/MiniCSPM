"""CIS 1.16 placeholder."""

from __future__ import annotations

from typing import Any, Dict, List

from settings import Settings

META = {
    "cis": "1.16",
    "version": ['v5_0']
}


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:  # pragma: no cover - TODO implement
    """TODO: Implement cis_1_16_securityhub_enabled check.

    Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html
    """
    raise NotImplementedError("CIS control 1.16 not yet implemented")
