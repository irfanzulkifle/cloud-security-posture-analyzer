"""Command-line entry point for Cloud Guardian."""

from __future__ import annotations

import argparse
from pathlib import Path

from cloud_guardian.analyzer import analyze_dataset


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze AWS-style security data and generate a posture report."
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path("data"),
        help="Directory containing aws_inventory.json, security_groups.csv, and vpc_flow_logs.csv.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/cloud_security_report.md"),
        help="Path for the generated Markdown report.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    findings, report = analyze_dataset(args.data_dir)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")

    print(f"Generated {args.output} with {len(findings)} findings.")


if __name__ == "__main__":
    main()
