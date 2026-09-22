# Scan demo

This is a small target project for exercising the `provtrail` scanner. It contains:

- `vulnerable_clone.js`: the existing C01 transformed vulnerable Axios proxy clone;
- `patched_clone.js`: the corresponding patched Axios function;
- `benign.js`: the existing hierarchy-demo authorization example.
- `candidates/`: C02–C30 materialized from the existing 30-candidate evaluation set;
- `candidates/manifest.json`: candidate IDs, transformations, CVEs, and expected statuses.

C10 and C30 were standalone class-method snippets in the evaluation fixture, so the
demo files place those method bodies inside a minimal JavaScript class.

From the repository root in PowerShell, with ProvTrail installed in the active
virtual environment and the repository corpus already built, run:

```powershell
$env:PROVTRAIL_DATA_DIR = (Resolve-Path corpus/data).Path
provtrail scan examples/scan_demo `
  --db-path corpus/data/corpus.db `
  --sarif-output examples/scan_demo/.provtrail/latest-scan.sarif `
  --ai-output examples/scan_demo/.provtrail/latest-scan.ai.txt
```

The first scan may build or load the local embedding index. Repeat the command to
observe cache reuse. Exit code 1 means the scan found actionable results.
`--db-path` selects the repository's populated corpus. Without it or
`PROVTRAIL_DATA_DIR`, a new app-data corpus can be empty and produce no findings.
The files are written under `examples/scan_demo/.provtrail/` alongside the JSON
and HTML reports. Open `latest-scan.ai.txt` directly for the compact text output,
or inspect `latest-scan.sarif` in a JSON viewer. Both contain automatic vulnerability
and manual-review findings, including any Ollama-dismissed reviews.

To regenerate only the exports from the saved JSON without scanning again, run:

```powershell
provtrail report examples/scan_demo `
  --sarif-output examples/scan_demo/.provtrail/latest-scan.sarif `
  --ai-output examples/scan_demo/.provtrail/latest-scan.ai.txt
```

`vulnerable_clone.js` is the positive control. `patched_clone.js` and `benign.js`
are controls for inspecting possible false positives or manual reviews.
