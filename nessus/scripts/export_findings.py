#!/usr/bin/env python3
"""Export normalized Nessus findings into final JSON contract."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def _counts_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    counter = Counter(
        str(item.get("severity_label", "Info"))
        for item in findings
    )
    counts = {level: int(counter.get(level, 0)) for level in SEVERITY_ORDER}
    return counts


def _sorted_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    order_index = {label: idx for idx, label in enumerate(SEVERITY_ORDER)}

    def _key(item: dict[str, Any]) -> tuple[int, str, str]:
        label = str(item.get("severity_label", "Info"))
        idx = order_index.get(label, len(SEVERITY_ORDER))
        return (idx, str(item.get("asset", "")), str(item.get("title", "")))

    return sorted(findings, key=_key)


def build_contract(findings: list[dict[str, Any]]) -> dict[str, Any]:
    sorted_findings = _sorted_findings(findings)
    return {
        "source": "nessus",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(sorted_findings),
        "counts_by_severity": _counts_by_severity(sorted_findings),
        "findings": sorted_findings,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Export normalized Nessus findings into the final JSON contract."
    )
    parser.add_argument("--input", required=True, help="Path to normalized findings JSON")
    parser.add_argument("--output", required=True, help="Path to final export JSON")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    with input_path.open("r", encoding="utf-8") as file_obj:
        findings = json.load(file_obj)

    if not isinstance(findings, list):
        raise ValueError("Input JSON must be a list of normalized findings")

    contract = build_contract(findings)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as file_obj:
        json.dump(contract, file_obj, indent=2)

    print(f"Exported {len(findings)} findings")
    print(f"Wrote contract JSON to {output_path}")


if __name__ == "__main__":
    main()