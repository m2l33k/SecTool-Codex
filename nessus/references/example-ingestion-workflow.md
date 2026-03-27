# Example Ingestion Workflow

```bash
python scripts/ingest_nessus_report.py --input scan.nessus --output out/raw_findings.json
python scripts/normalize_findings.py --input out/raw_findings.json --output out/normalized_findings.json
python scripts/export_findings.py --input out/normalized_findings.json --output out/export_findings.json
```

Expected sequence:

1. Ingest raw Nessus XML to JSON records.
2. Normalize severity and schema fields.
3. Export final contract JSON for downstream systems.