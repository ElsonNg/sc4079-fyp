# provtrail

A CLI tool for detecting JavaScript vulnerability clones (patched-but-reintroduced or renamed/reworded vulnerable code) against a corpus built from real CVE fix commits.

## CLI

The detector can be run against a JavaScript codebase with incremental scan state:

```bash
PYTHONPATH=. .venv/bin/python -m cli scan /path/to/project --output scan.json
```

Repeat the command to reuse unchanged function verdicts. Use `--json` to print the
structured report to stdout. Corpus maintenance commands are:

```bash
PYTHONPATH=. .venv/bin/python -m cli corpus stats
PYTHONPATH=. .venv/bin/python -m cli corpus build
```

Generated embedding indexes and local scan state are intentionally excluded from Git.
