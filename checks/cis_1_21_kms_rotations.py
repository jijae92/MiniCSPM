"""CIS 1.21 placeholder."""

from __future__ import annotations

from typing import Any, Dict, List

from settings import Settings

META = {
    "cis": "1.21",
    "version": ['v5_0']
}


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:  # pragma: no cover - TODO implement
    """TODO: Implement cis_1_21_kms_rotations check.

    Reference: https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html
    """
    raise NotImplementedError("CIS control 1.21 not yet implemented")
