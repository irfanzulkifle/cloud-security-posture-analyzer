"""Analyze small AWS-style datasets for network and cloud security risks."""

from __future__ import annotations

import csv
import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


RISK_POINTS = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 1,
}

REMOTE_ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
DATABASE_PORTS = {3306: "MySQL", 5432: "PostgreSQL"}
SENSITIVE_PORTS = DATABASE_PORTS | {6379: "Redis", 9200: "Elasticsearch", 5601: "Kibana"}
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
CIS_REFS = {
    "iam_mfa": "CIS AWS Foundations Benchmark v1.4.0 1.10 - Ensure MFA is enabled for all users that have a console password",
    "iam_key_rotation": "CIS AWS Foundations Benchmark v1.4.0 1.14 - Ensure access keys are rotated every 90 days or less",
    "s3_public_access": "CIS AWS Foundations Benchmark v1.4.0 2.1.5 - Ensure S3 buckets are configured with Block Public Access",
    "security_group_admin": "CIS AWS Foundations Benchmark v1.4.0 5.2 - Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports",
}


@dataclass(frozen=True)
class Finding:
    severity: str
    title: str
    resource: str
    evidence: str
    recommendation: str
    compliance_refs: tuple[str, ...] = ()

    @property
    def points(self) -> int:
        return RISK_POINTS[self.severity]


def load_inventory(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def load_security_groups(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def load_flow_logs(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = []
        for row in csv.DictReader(handle):
            row["dstport"] = int(row["dstport"])
            row["packets"] = int(row["packets"])
            rows.append(row)
        return rows


def is_public_cidr(cidr: str) -> bool:
    network = ipaddress.ip_network(cidr, strict=False)
    return network == ipaddress.ip_network("0.0.0.0/0")


def is_private_ip(address: str) -> bool:
    ip_addr = ipaddress.ip_address(address)
    return any(ip_addr in network for network in PRIVATE_RANGES)


def analyze_security_groups(rows: Iterable[dict]) -> list[Finding]:
    findings: list[Finding] = []

    for row in rows:
        group_id = row["group_id"]
        port = int(row["port"])
        cidr = row["cidr"]
        direction = row["direction"].lower()

        if direction != "ingress" or not is_public_cidr(cidr):
            continue

        if port in REMOTE_ADMIN_PORTS:
            findings.append(
                Finding(
                    severity="critical",
                    title=f"Public {REMOTE_ADMIN_PORTS[port]} access",
                    resource=group_id,
                    evidence=f"{group_id} allows {cidr} to TCP/{port}.",
                    recommendation=(
                        "Restrict administrative access to a VPN, bastion host, "
                        "or approved office IP range."
                    ),
                    compliance_refs=(CIS_REFS["security_group_admin"],),
                )
            )
        elif port in SENSITIVE_PORTS:
            service = SENSITIVE_PORTS[port]
            findings.append(
                Finding(
                    severity="high",
                    title=f"Public {service} access",
                    resource=group_id,
                    evidence=f"{group_id} allows {cidr} to TCP/{port}.",
                    recommendation="Place the service on private subnets and limit access by source security group.",
                )
            )

    return findings


def analyze_inventory(inventory: dict) -> list[Finding]:
    findings: list[Finding] = []

    for bucket in inventory.get("s3_buckets", []):
        if bucket.get("public_access") is True:
            findings.append(
                Finding(
                    severity="high",
                    title="Public S3 bucket",
                    resource=bucket["name"],
                    evidence=f"{bucket['name']} has public_access=true.",
                    recommendation="Enable S3 Block Public Access and review bucket policies.",
                    compliance_refs=(CIS_REFS["s3_public_access"],),
                )
            )

        if bucket.get("encryption") != "aws:kms":
            findings.append(
                Finding(
                    severity="medium",
                    title="Bucket not encrypted with customer-managed KMS",
                    resource=bucket["name"],
                    evidence=f"{bucket['name']} encryption is {bucket.get('encryption')}.",
                    recommendation="Use SSE-KMS for sensitive data and rotate keys according to policy.",
                )
            )

    for user in inventory.get("iam_users", []):
        if user.get("mfa_enabled") is False and "AdministratorAccess" in user.get("policies", []):
            findings.append(
                Finding(
                    severity="critical",
                    title="Admin IAM user without MFA",
                    resource=user["username"],
                    evidence=f"{user['username']} has AdministratorAccess and mfa_enabled=false.",
                    recommendation="Require MFA for all privileged identities and prefer short-lived roles.",
                    compliance_refs=(
                        CIS_REFS["iam_mfa"],
                        "CIS AWS Foundations Benchmark v1.4.0 1.16 - Ensure IAM policies that allow full administrative privileges are not attached",
                    ),
                )
            )

        if user.get("access_key_age_days", 0) > 90:
            findings.append(
                Finding(
                    severity="medium",
                    title="Old IAM access key",
                    resource=user["username"],
                    evidence=f"{user['username']} key age is {user['access_key_age_days']} days.",
                    recommendation="Rotate long-lived access keys and move automation to IAM roles where possible.",
                    compliance_refs=(CIS_REFS["iam_key_rotation"],),
                )
            )

    return findings


def analyze_flow_logs(rows: Iterable[dict]) -> list[Finding]:
    findings: list[Finding] = []
    rejected_public_admin: dict[tuple[str, int], int] = {}

    for row in rows:
        if row["action"] != "REJECT":
            continue
        if is_private_ip(row["srcaddr"]):
            continue
        if row["dstport"] not in REMOTE_ADMIN_PORTS:
            continue

        key = (row["dstaddr"], row["dstport"])
        rejected_public_admin[key] = rejected_public_admin.get(key, 0) + row["packets"]

    for (dstaddr, port), packets in rejected_public_admin.items():
        severity = "high" if packets >= 50 else "medium"
        findings.append(
            Finding(
                severity=severity,
                title=f"Repeated rejected public {REMOTE_ADMIN_PORTS[port]} traffic",
                resource=f"{dstaddr}:{port}",
                evidence=f"{packets} rejected packets from public IP space targeted TCP/{port}.",
                recommendation="Confirm the instance is not internet-facing and investigate repeated scan sources.",
                compliance_refs=(CIS_REFS["security_group_admin"],),
            )
        )

    return findings


def score_findings(findings: Iterable[Finding]) -> int:
    return sum(finding.points for finding in findings)


def risk_rating(score: int) -> str:
    if score >= 35:
        return "Critical"
    if score >= 20:
        return "High"
    if score >= 10:
        return "Medium"
    return "Low"


def build_markdown_report(findings: list[Finding]) -> str:
    ordered = sorted(findings, key=lambda item: (-item.points, item.resource, item.title))
    score = score_findings(ordered)
    lines = [
        "# Cloud Security Posture Report",
        "",
        f"Overall risk rating: **{risk_rating(score)}**",
        f"Risk score: **{score}**",
        f"Findings: **{len(ordered)}**",
        "",
        "## Executive Summary",
        "",
        "This report reviews AWS-style inventory, security group rules, and VPC Flow Log samples. "
        "Findings are prioritized by likely business impact, remediation urgency, and CIS AWS Foundations alignment.",
        "",
        "## Compliance Coverage",
        "",
        "- Framework: CIS AWS Foundations Benchmark v1.4.0 alignment",
        "- Note: This project performs educational checks against sample data and is not a substitute for a full CIS audit.",
        "",
        "## Findings",
        "",
    ]

    if not ordered:
        lines.append("No findings detected in the supplied datasets.")
        return "\n".join(lines) + "\n"

    for index, finding in enumerate(ordered, start=1):
        lines.extend(
            [
                f"### {index}. {finding.title}",
                "",
                f"- Severity: **{finding.severity.upper()}**",
                f"- Resource: `{finding.resource}`",
                f"- Evidence: {finding.evidence}",
                f"- Recommendation: {finding.recommendation}",
                f"- Compliance: {format_compliance_refs(finding)}",
                "",
            ]
        )

    return "\n".join(lines)


def format_compliance_refs(finding: Finding) -> str:
    if not finding.compliance_refs:
        return "No direct CIS mapping; included as a security best-practice finding."
    return "; ".join(finding.compliance_refs)


def analyze_dataset(data_dir: Path) -> tuple[list[Finding], str]:
    inventory = load_inventory(data_dir / "aws_inventory.json")
    security_groups = load_security_groups(data_dir / "security_groups.csv")
    flow_logs = load_flow_logs(data_dir / "vpc_flow_logs.csv")

    findings = [
        *analyze_inventory(inventory),
        *analyze_security_groups(security_groups),
        *analyze_flow_logs(flow_logs),
    ]
    return findings, build_markdown_report(findings)
