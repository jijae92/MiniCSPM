"""CIS 1.8 placeholder."""

from __future__ import annotations

from typing import Any, Dict, List

from settings import Settings

META = {
    "cis": "1.8",
    "version": ['v1_5']
}


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:  # pragma: no cover - TODO implement
    """TODO: Implement cis_1_8_vpc_flow_logs check.

    Reference: https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html
    """
    raise NotImplementedError("CIS control 1.8 not yet implemented")
