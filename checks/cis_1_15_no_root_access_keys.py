"""CIS 1.15 placeholder."""

from __future__ import annotations

from typing import Any, Dict, List

from settings import Settings


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:  # pragma: no cover - TODO implement
    """TODO: Implement cis_1_15_no_root_access_keys check.

    Reference: https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html
    """
    raise NotImplementedError("CIS control 1.15 not yet implemented")
