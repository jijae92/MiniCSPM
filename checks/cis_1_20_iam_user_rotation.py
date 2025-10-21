"""CIS 1.20 placeholder."""

from __future__ import annotations

from typing import Any, Dict, List

from settings import Settings

META = {
    "cis": "1.20",
    "version": ['v5_0']
}


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:  # pragma: no cover - TODO implement
    """TODO: Implement cis_1_20_iam_user_rotation check.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/credstoring.html
    """
    raise NotImplementedError("CIS control 1.20 not yet implemented")
