"""CIS 1.19 placeholder."""

from __future__ import annotations

from typing import Any, Dict, List

from settings import Settings


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:  # pragma: no cover - TODO implement
    """TODO: Implement cis_1_19_cloudtrail_enabled check.

    Reference: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-an-organizational-trail.html
    """
    raise NotImplementedError("CIS control 1.19 not yet implemented")
