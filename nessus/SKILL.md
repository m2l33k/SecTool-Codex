# Nessus Ingestion Skill

## Purpose

Convert Nessus scan exports into normalized vulnerability findings and a stable JSON contract.

## Folder Layout

- `agents/openai.yaml`: agent config for this workflow.
- `references/`: parsing, normalization, and export conventions.
- `scripts/ingest_nessus_report.py`: parse `.nessus` XML into raw JSON findings.
- `scripts/normalize_findings.py`: map fields and severities into normalized schema.
- `scripts/export_findings.py`: generate final export contract JSON.

## Workflow

1. Ingest Nessus report file.
2. Normalize findings.
3. Export final JSON payload.

## Usage

```bash
python scripts/ingest_nessus_report.py --input scan.nessus --output out/raw.json
python scripts/normalize_findings.py --input out/raw.json --output out/normalized.json
python scripts/export_findings.py --input out/normalized.json --output out/export.json
```