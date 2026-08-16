# provtrail

A CLI tool for detecting JavaScript vulnerability clones (patched-but-reintroduced or renamed/reworded vulnerable code) against a corpus built from real CVE fix commits.

## CLI

The detector can be run against a JavaScript codebase with incremental scan state:

```bash
PYTHONPATH=. .venv/bin/python -m cli scan /path/to/project --output scan.json
```

The default scan summary uses an npm-audit-style layout. It also saves the structured
result to `/path/to/project/.provtrail/latest-scan.json`; repeat the command to reuse
unchanged function verdicts. A scan exits non-zero when it finds a flagged or
manual-review result. Use `--json` to print the structured scan report to stdout.

Inspect CVE, affected-version, fixed-version, score, and provenance details without
rerunning the detector:

```bash
PYTHONPATH=. .venv/bin/python -m cli report /path/to/project --verbose
```

The report command also accepts a saved JSON file directly. Use `--include-cleared` to
include cleared functions in the detailed output. Corpus maintenance commands are:

```bash
PYTHONPATH=. .venv/bin/python -m cli corpus stats
PYTHONPATH=. .venv/bin/python -m cli corpus build
```

Generated embedding indexes and local scan state are intentionally excluded from Git.
