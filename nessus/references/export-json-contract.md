# Export JSON Contract

Top-level structure:

```json
{
  "source": "nessus",
  "generated_at": "ISO-8601 UTC",
  "counts_by_severity": {
    "Critical": 0,
    "High": 0,
    "Medium": 0,
    "Low": 0,
    "Info": 0
  },
  "findings": []
}
```

Each finding object should include:

- `finding_id`
- `asset`
- `title`
- `severity_label`
- `severity_score`
- `description`
- `solution`
- `evidence`
- `references`