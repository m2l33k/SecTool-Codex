# Nessus Report Format

Nessus `.nessus` reports are XML files that usually include:

- `ReportHost`: scanned host container
- `HostProperties`: host metadata
- `ReportItem`: vulnerability record on a host

Common `ReportItem` fields:

- `pluginID`, `pluginName`, `pluginFamily`
- `severity` (numeric)
- `port`, `protocol`, `svc_name`
- `risk_factor`
- `synopsis`, `description`, `solution`
- `plugin_output`
- `cve`, `bid`, `xref`

Practical parser requirement:

- Keep one record per `ReportItem`
- Copy host identity from parent `ReportHost`
- Preserve raw textual evidence (`plugin_output`)