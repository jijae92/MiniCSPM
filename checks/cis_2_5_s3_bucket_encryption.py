"""CIS 2.5 placeholder."""

from __future__ import annotations

from typing import Any, Dict, List

from settings import Settings

META = {
    "cis": "2.5",
    "version": ['v5_0']
}


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:  # pragma: no cover - TODO implement
    """TODO: Implement cis_2_5_s3_bucket_encryption check.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html
    """
    raise NotImplementedError("CIS control 2.5 not yet implemented")
