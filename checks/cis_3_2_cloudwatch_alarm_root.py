"""CIS 3.2 placeholder."""

from __future__ import annotations

from typing import Any, Dict, List

from settings import Settings

META = {
    "cis": "3.2",
    "version": ['v5_0']
}


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:  # pragma: no cover - TODO implement
    """TODO: Implement cis_3_2_cloudwatch_alarm_root check.

    Reference: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html
    """
    raise NotImplementedError("CIS control 3.2 not yet implemented")
