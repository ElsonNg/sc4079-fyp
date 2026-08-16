# provtrail

A CLI tool for detecting JavaScript vulnerability clones (patched-but-reintroduced or renamed/reworded vulnerable code) against a corpus built from real CVE fix commits.

## CLI

The detector can be run against a JavaScript codebase with incremental scan state:

```bash
PYTHONPATH=. .venv/bin/python -m cli scan /path/to/project --output scan.json
```

The default scan summary uses an npm-audit-style layout. Every scan saves both the
structured result and a self-contained, offline HTML report:

```text
/path/to/project/.provtrail/latest-scan.json
/path/to/project/.provtrail/latest-scan.html
```

Open the HTML file directly in a browser to explore the project tree, inspect findings,
and follow evidence-led recommendations. Use `--output scan.json` to move both artifacts
or `--html-output report.html` to override only the HTML path. Repeat the command to reuse
unchanged function verdicts. A scan exits non-zero when it finds a flagged or manual-review
result. Use `--json` to print the structured scan report to stdout.

Inspect CVE, affected-version, fixed-version, score, and provenance details without
rerunning the detector:

```bash
PYTHONPATH=. .venv/bin/python -m cli report /path/to/project --verbose
```

The report command also accepts a saved JSON file directly. Use `--include-cleared` to
include cleared functions in the detailed output. Rebuild an older corpus once to
backfill advisory titles, descriptions, and canonical links used by the HTML report.
Corpus maintenance commands are:

```bash
PYTHONPATH=. .venv/bin/python -m cli corpus stats
PYTHONPATH=. .venv/bin/python -m cli corpus build
```

Generated embedding indexes and local scan state are intentionally excluded from Git.
