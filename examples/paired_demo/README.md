# Paired scan demos

`vulnerable/` and `patched/` are two small projects built from three matched
Tier 2 fixture pairs. Each project has two JavaScript files with several
functions per file, including three neutral helpers. The shared `manifest.json`
records each target function, advisory and fix commit, so an unrelated finding
cannot pass as detection of the intended vulnerability.

From the repository root in PowerShell, using an installed `provtrail` command
and the populated repository corpus:

```powershell
$env:PROVTRAIL_DATA_DIR = (Resolve-Path corpus/data).Path

provtrail scan examples/paired_demo/vulnerable `
  --db-path corpus/data/corpus.db `
  --sarif-output examples/paired_demo/vulnerable/.provtrail/latest-scan.sarif `
  --ai-output examples/paired_demo/vulnerable/.provtrail/latest-scan.ai.txt

provtrail scan examples/paired_demo/patched `
  --db-path corpus/data/corpus.db `
  --sarif-output examples/paired_demo/patched/.provtrail/latest-scan.sarif `
  --ai-output examples/paired_demo/patched/.provtrail/latest-scan.ai.txt

python examples/paired_demo/check.py
```

The vulnerable scan currently reports three automatic vulnerabilities and three
neutral functions for manual review. The patched scan reports three patched
boundaries and the same three neutral manual reviews. Both scans therefore exit
1. This review noise is visible on purpose. `check.py` requires the exact
fix-boundary verdict for each labeled function, rejects automatic vulnerability
verdicts for the neutral helpers, and checks every actionable function's SARIF
and AI location. Generated reports are saved in each project's `.provtrail/`
directory and are ignored by Git.

These are curated examples of a clear vulnerable/patched contrast, not an
accuracy benchmark. The larger `examples/scan_demo/` remains useful for
exploring harder transformations and manual-review behavior.
