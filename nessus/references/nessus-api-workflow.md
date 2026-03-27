# Nessus API Workflow

Typical API workflow:

1. Authenticate and retrieve API token.
2. List scans and pick target scan id.
3. Request export with desired format (`nessus`, `csv`, or `json` depending on endpoint).
4. Poll export status until ready.
5. Download export payload.
6. Run ingestion -> normalization -> export contract pipeline.

Operational notes:

- Treat export as immutable input artifact.
- Store scan id and export id for traceability.
- Record generation timestamp in final JSON export.