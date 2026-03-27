#!/usr/bin/env python3
"""Normalize raw Nessus findings into a stable schema."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

SEVERITY_LABELS = {
    0: "Info",
    1: "Low",
    2: "Medium",
    3: "High",
    4: "Critical",
}

RISK_TO_SCORE = {
    "NONE": 0,
    "INFO": 0,
    "INFORMATIONAL": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _severity_score(item: dict[str, Any]) -> int:
    score = _safe_int(item.get("severity"), -1)
    if score in SEVERITY_LABELS:
        return score

    risk_factor = str(item.get("risk_factor", "")).strip().upper()
    return RISK_TO_SCORE.get(risk_factor, 0)


def _severity_label(score: int) -> str:
    return SEVERITY_LABELS.get(score, "Info")


def _finding_key(item: dict[str, Any]) -> str:
    raw_key = "|".join(
        [
            str(item.get("asset", "")),
            str(item.get("plugin_id", "")),
            str(item.get("port", "")),
            str(item.get("protocol", "")),
        ]
    )
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:24]


def _references(item: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for key in ("cve", "bid", "xref", "see_also"):
        value = item.get(key, [])
        if isinstance(value, list):
            refs.extend(str(x).strip() for x in value if str(x).strip())
        elif isinstance(value, str) and value.strip():
            refs.append(value.strip())

    seen: set[str] = set()
    deduped: list[str] = []
    for ref in refs:
        if ref not in seen:
            seen.add(ref)
            deduped.append(ref)
    return deduped


def normalize_findings(raw_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: dict[str, dict[str, Any]] = {}

    for item in raw_findings:
        score = _severity_score(item)
        finding_id = _finding_key(item)

        finding = {
            "source": "nessus",
            "finding_id": finding_id,
            "asset": item.get("asset", ""),
            "plugin_id": str(item.get("plugin_id", "")),
            "title": item.get("plugin_name", ""),
            "severity_score": score,
            "severity_label": _severity_label(score),
            "description": item.get("description", "") or item.get("synopsis", ""),
            "solution": item.get("solution", ""),
            "evidence": item.get("plugin_output", ""),
            "port": _safe_int(item.get("port"), 0),
            "protocol": item.get("protocol", ""),
            "references": _references(item),
            "raw": {
                "risk_factor": item.get("risk_factor", ""),
                "plugin_family": item.get("plugin_family", ""),
                "host_name": item.get("host_name", ""),
                "host_ip": item.get("host_ip", ""),
                "host_fqdn": item.get("host_fqdn", ""),
            },
        }

        if finding_id not in normalized:
            normalized[finding_id] = finding
            continue

        current = normalized[finding_id]
        if finding["severity_score"] > current["severity_score"]:
            current["severity_score"] = finding["severity_score"]
            current["severity_label"] = finding["severity_label"]

        if finding["evidence"] and finding["evidence"] not in str(current["evidence"]):
            merged_evidence = "\n\n".join(
                [x for x in [str(current["evidence"]).strip(), str(finding["evidence"]).strip()] if x]
            )
            current["evidence"] = merged_evidence

        merged_refs = list(dict.fromkeys([*current.get("references", []), *finding.get("references", [])]))
        current["references"] = merged_refs

    return list(normalized.values())


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Normalize raw Nessus findings into a stable JSON schema."
    )
    parser.add_argument("--input", required=True, help="Path to raw findings JSON")
    parser.add_argument("--output", required=True, help="Path to normalized findings JSON")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    with input_path.open("r", encoding="utf-8") as file_obj:
        raw = json.load(file_obj)

    if not isinstance(raw, list):
        raise ValueError("Input JSON must be a list of findings")

    normalized = normalize_findings(raw)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as file_obj:
        json.dump(normalized, file_obj, indent=2)

    print(f"Normalized {len(raw)} raw findings into {len(normalized)} findings")
    print(f"Wrote normalized findings to {output_path}")


if __name__ == "__main__":
    main()