# provtrail

A CLI tool for detecting JavaScript and TypeScript vulnerability clones against strictly
evidence-attributed vulnerable origins from the npm JavaScript/TypeScript ecosystem.

## CLI

GitHub requests use `GITHUB_TOKEN` from the project-root `.env` file. A token
already set in the process environment takes precedence. The `.env` file is ignored
by Git.

For engineers extending the tool, `cli/main.py` defines arguments and dispatches
commands. Execution lives in `cli/commands/scan.py`, `report.py`, and `corpus.py`.
The scan command calls `pipeline/scanning/scanner.py`, which coordinates the
detector in `pipeline/controller/region_detection.py`. The scan command then writes
the JSON and HTML reports. To follow a scan, read `scan_directory()` first:

1. `discovery.py` extracts JavaScript and TypeScript functions.
2. `cache.py` loads the snapshot and reusable detector results.
3. `scanner.py` reuses or detects each function, then applies project evidence.
4. `project_context.py` checks package manifests and imports.
5. `scanner.py` saves scan state and returns findings to the CLI for reporting.

The old `pipeline/controller/scanning.py`, `incremental.py` and
`project_evidence.py` imports remain available during the migration.

Inside `RegionDetector.detect()`, follow hash lookup, region retrieval, verification,
boundary classification and lineage attribution in that order. The extracted
components live in `pipeline/detection/`:

- `hashing.py` builds results for deterministic matches.
- `retrieval.py` groups and limits reference pairs for verification.
- `lineage.py` attributes source lineage and lists associated packages.
- `priority.py` chooses reporting priority from the resulting evidence.

The detector's `_verify_regions()` and `_classify_boundaries()` methods coordinate
the detailed checks. The optional local correspondence fallback runs only after
boundary classification remains uncertain and its eligibility gates pass.
Batch detection shares retrieval first, then rejoins `detect()` for each function.

Region verification lives in `pipeline/detection/verification/`: `verifier.py`
coordinates scoring, `classification.py` decides boundary states, and the other
modules own structural/token scores, edit distance, evidence selection and fallbacks.

The detector scans `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.mts`, and `.cts`
files with incremental scan state:

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
PYTHONPATH=. .venv/bin/python -m cli corpus ingest-klaban
PYTHONPATH=. .venv/bin/python -m cli corpus index
```

`corpus build` discovers every reviewed, non-withdrawn npm advisory automatically. It
admits entries only after GitHub Advisory Database, OSV, npm tarball, repository, release,
commit-ancestry, focused-diff, parser, and executable-AST checks agree. `--package` is a
diagnostic restriction and does not bypass any check. Severity, popularity, maintenance,
and the post-admission high-impact cohort are metadata rather than admission gates.

Successful builds are first written to a versioned directory under
`corpus/data/snapshots/`. The database, native/type-erased retrieval map, source and
artifact hashes, policy manifest, attrition report, quarantine ledger, and complete and
high-impact cohort counts are checked before `current.json` and the active database are
replaced atomically. Failed builds do not promote a partial snapshot.

Native source is authoritative. An exact native vulnerable-side hash can produce
`Flagged (Exact)`; a TypeScript-to-JavaScript match through the type-erased runtime
representation can produce only `Flagged (Inferred)`. The report's **View info** dialog
shows both source language and representation.

The initial corpus is coverage-first and has not yet undergone manual sampling,
precision confidence-interval measurement, reviewer-consistency analysis, LLM corpus
review, or independent vulnerability-semantic/exploitability validation. Consequently,
an entry is described as a “strictly evidence-attributed vulnerable origin,” not an
independently proven exploitable function, and `Flagged (Exact)` is not a statistically
validated corpus-wide guarantee. The immutable provenance and quarantine artifacts are
retained for that later evaluation.

The separate `corpus ingest-klaban` evaluation utility is not used by `corpus build`.
It reads the bundled manually confirmed Klaban dataset, replaces
previously imported Klaban rows in `corpus/data/corpus.db`, and builds both the
whole-function and AST-region FAISS embedding indexes. Pass `--skip-index` to perform
only the SQLite import, or `--db-path` and the index-directory options to write isolated
artifacts.
Use `--device cpu` when the platform's MPS/CUDA backend is unavailable or unstable.
Use `--skip-region-index` when only the whole-function FAISS index is required.

Long functions are indexed with bounded, diagnostic-aware windows so code around the
security fix remains retrievable even when it occurs far beyond the function prefix.
Kluban overlap analysis and benchmarking are deferred to the later evaluation phase. The
existing evaluation utility can be run independently with:

```bash
PYTHONPATH=. .venv/bin/python scripts/evaluate_klaban_retrieval.py --k 10
```

The evaluator prints running hit rates, elapsed time, and ETA every 10 queries. Use
`--progress-every 1` for every query or `--progress-every 0` for quiet operation.

Generated embedding indexes and local scan state are intentionally excluded from Git.
