# Severity Mapping

Nessus can expose severity as numeric values and textual factors.

Suggested normalized mapping:

- `0` -> `Info`
- `1` -> `Low`
- `2` -> `Medium`
- `3` -> `High`
- `4` -> `Critical`

Fallback behavior:

- If numeric severity missing, map from `risk_factor` text.
- Unknown values should map to `Info` with score `0`.