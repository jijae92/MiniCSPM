from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

HEADER = [
    "timestamp",
    "account_id",
    "control_id",
    "title",
    "severity",
    "status",
    "resource_ids",
    "notes",
]

ROWS = [
    [
        datetime(2024, 1, 1).isoformat(),
        "123456789012",
        "CIS-1.1",
        "Root account MFA enabled",
        "HIGH",
        "FAIL",
        "123456789012",
        "{\"mfa_enabled\": false}",
    ],
    [
        datetime(2024, 1, 1).isoformat(),
        "123456789012",
        "CIS-1.2",
        "No root access keys",
        "MEDIUM",
        "PASS",
        "",
        "",
    ],
]

OUTPUT_PATH = Path("sample_out.csv")


def main() -> None:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(HEADER)
        writer.writerows(ROWS)


if __name__ == "__main__":
    main()
