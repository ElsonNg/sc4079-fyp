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

### Local second opinions for manual review

Manual-review findings can optionally include an independent relevance review from a local
Ollama model. Flagged findings do not invoke the LLM. Install the model once, keep Ollama
running, and opt in when scanning:

```bash
ollama pull qwen3:8b
PYTHONPATH=. .venv/bin/python -m cli scan /path/to/project --explain-review
```

The model compares the advisory's security mechanism with the project, vulnerable, and
patched code. It assigns relevance tier 1 (totally irrelevant), 2 (potentially relevant),
or 3 (definitely relevant), shown as an LLM verdict of Dismissed, Needs review, or Flagged.
Detector scores and confidence are deliberately excluded from its prompt so this remains
a second opinion. The LLM verdict does not change the deterministic finding status,
severity, scores, process exit code, or recommendations. If Ollama is unavailable or
returns invalid output, the scan completes, records the explanation as unavailable, and
prints a warning.

Successful explanations are content-addressed and reused from
`.provtrail/review-explanations.json`. The cache key includes the model, prompt version,
and evidence bundle, so changed evidence is explained again. The generated explanation is
also embedded in the JSON and self-contained HTML artifacts.

Use `--ollama-model`, `--ollama-host`, and `--ollama-timeout` to override the defaults.
`PROVTRAIL_OLLAMA_MODEL` and `OLLAMA_HOST` provide environment-variable equivalents for
the model and host. The default endpoint is local (`http://127.0.0.1:11434`); provtrail
does not send review evidence to a hosted model by default. Network access is needed only
to install or update the Ollama model. Once the model and vulnerability corpus are present,
scanning, explanation generation, and viewing the report work offline.

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
