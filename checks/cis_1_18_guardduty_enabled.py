"""CIS 1.18 placeholder."""

from __future__ import annotations

from typing import Any, Dict, List

from settings import Settings

META = {
    "cis": "1.18",
    "version": ['v5_0']
}


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:  # pragma: no cover - TODO implement
    """TODO: Implement cis_1_18_guardduty_enabled check.

    Reference: https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html
    """
    raise NotImplementedError("CIS control 1.18 not yet implemented")
