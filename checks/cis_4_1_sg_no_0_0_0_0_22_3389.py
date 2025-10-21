"""CIS 4.1 - Security groups should not allow 0.0.0.0/0 to ports 22 or 3389."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from botocore.exceptions import ClientError

from settings import Settings

TARGET_PORTS = {22, 3389}
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def run(*, settings: Settings, clients: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Scan security groups for overly permissive rules."""
    checked_at = datetime.now(timezone.utc)
    ec2 = clients["ec2"]
    try:
        response = ec2.describe_security_groups()
        security_groups = response.get("SecurityGroups", [])
        offenders = _find_offenders(security_groups)
        status = "PASS" if not offenders else "FAIL"
        evidence = {"open_rules": offenders}
    except ClientError as error:
        status = "WARN"
        evidence = {"error": str(error)}

    finding = {
        "id": "CIS-4.1",
        "title": "Security groups restrict SSH/RDP",
        "cis": "4.1",
        "service": "ec2",
        "severity": "HIGH",
        "status": status,
        "resource_ids": [rule["group_id"] for rule in evidence.get("open_rules", [])] if isinstance(evidence, dict) else [],
        "evidence": evidence,
        "remediable": True,
        "remediation_action": "revoke_sg_open_admin_ports",
        "references": [
            "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html",
        ],
        "checked_at": checked_at,
    }
    return [finding]


def _find_offenders(groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    offenders: List[Dict[str, Any]] = []
    for group in groups:
        group_id = group.get("GroupId")
        for permission in group.get("IpPermissions", []):
            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")
            ip_protocol = permission.get("IpProtocol")
            if ip_protocol not in ("tcp", "-1"):
                continue
            ports = TARGET_PORTS if ip_protocol == "-1" else {from_port, to_port}
            if not ports & TARGET_PORTS:
                continue
            if any(range_entry.get("CidrIp") in OPEN_CIDRS for range_entry in permission.get("IpRanges", [])) or any(
                range_entry.get("CidrIpv6") in OPEN_CIDRS for range_entry in permission.get("Ipv6Ranges", [])
            ):
                offenders.append(
                    {
                        "group_id": group_id,
                        "from_port": from_port,
                        "to_port": to_port,
                        "protocol": ip_protocol,
                    }
                )
    return offenders
