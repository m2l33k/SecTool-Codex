#!/usr/bin/env python3
"""Ingest Nessus .nessus XML reports and export raw findings as JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET


def _text(node: ET.Element, tag: str) -> str:
    child = node.find(tag)
    if child is None or child.text is None:
        return ""
    return child.text.strip()


def _all_texts(node: ET.Element, tag: str) -> list[str]:
    values: list[str] = []
    for child in node.findall(tag):
        if child.text:
            text = child.text.strip()
            if text:
                values.append(text)
    return values


def _to_int(value: str | None, default: int = 0) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _host_properties(report_host: ET.Element) -> dict[str, str]:
    props: dict[str, str] = {}
    host_props = report_host.find("HostProperties")
    if host_props is None:
        return props

    for tag in host_props.findall("tag"):
        name = tag.attrib.get("name", "").strip()
        text = (tag.text or "").strip()
        if name:
            props[name] = text
    return props


def parse_nessus_report(input_path: Path) -> list[dict[str, Any]]:
    tree = ET.parse(input_path)
    root = tree.getroot()

    findings: list[dict[str, Any]] = []
    for report_host in root.findall(".//ReportHost"):
        host_name = report_host.attrib.get("name", "")
        host_props = _host_properties(report_host)

        asset = (
            host_props.get("host-ip")
            or host_props.get("host-fqdn")
            or host_props.get("netbios-name")
            or host_name
        )

        for item in report_host.findall("ReportItem"):
            finding = {
                "source": "nessus",
                "asset": asset,
                "host_name": host_name,
                "host_ip": host_props.get("host-ip", ""),
                "host_fqdn": host_props.get("host-fqdn", ""),
                "plugin_id": item.attrib.get("pluginID", ""),
                "plugin_name": item.attrib.get("pluginName", ""),
                "plugin_family": item.attrib.get("pluginFamily", ""),
                "port": _to_int(item.attrib.get("port"), 0),
                "protocol": item.attrib.get("protocol", ""),
                "service": item.attrib.get("svc_name", ""),
                "severity": _to_int(item.attrib.get("severity"), 0),
                "risk_factor": _text(item, "risk_factor"),
                "synopsis": _text(item, "synopsis"),
                "description": _text(item, "description"),
                "solution": _text(item, "solution"),
                "plugin_output": _text(item, "plugin_output"),
                "cve": _all_texts(item, "cve"),
                "bid": _all_texts(item, "bid"),
                "xref": _all_texts(item, "xref"),
                "see_also": _all_texts(item, "see_also"),
            }
            findings.append(finding)

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse a Nessus .nessus report and export raw findings as JSON."
    )
    parser.add_argument("--input", required=True, help="Path to input .nessus file")
    parser.add_argument("--output", required=True, help="Path to output JSON file")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    findings = parse_nessus_report(input_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as file_obj:
        json.dump(findings, file_obj, indent=2)

    print(f"Ingested {len(findings)} findings from {input_path}")
    print(f"Wrote raw findings to {output_path}")


if __name__ == "__main__":
    main()