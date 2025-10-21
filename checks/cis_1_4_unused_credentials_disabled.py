"""CIS 1.4 placeholder."""

from __future__ import annotations

from typing import Any, Dict, List

from settings import Settings


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:  # pragma: no cover - TODO implement
    """TODO: Implement cis_1_4_unused_credentials_disabled check.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#rotate-credentials
    """
    raise NotImplementedError("CIS control 1.4 not yet implemented")
