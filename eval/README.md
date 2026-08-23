# Candidate subset fixtures

`candidate_subset_30.jsonl` is a reproducible positive-only benchmark fixture for
the vulnerable-clone detector.

It contains 30 candidate functions derived from 22 distinct vulnerable corpus
entries. Each record retains the corpus vulnerable and patched snapshots, CVE/GHSA
identity, affected/fixed library versions, fix commit, file/function provenance,
diagnostic lines, source digests, the transformation family, and the expected
outcome (`flagged`).

The generator applies deterministic, source-aware transformations covering:

- identifier renaming;
- dead-branch insertion;
- return splitting;
- boolean and ternary expansion;
- single-line block rewriting;
- independent constructor-assignment reordering; and
- formatting changes.

Regenerate it from the repository root with:

```text
PYTHONPATH=. .venv/bin/python scripts/generate_candidate_subset.py
```

The generator verifies that every candidate differs from its vulnerable source and
is parseable by Tree-sitter JavaScript, including class-method snippets that need a
synthetic wrapper. This is a positive structural-clone fixture, not a runtime
semantic-equivalence proof and not a complete accuracy benchmark. A separate
patched/benign hard-negative set should be evaluated alongside it.

The current-methodology baseline is produced with:

```text
PYTHONPATH=. .venv/bin/python -u scripts/validate_candidate_subset.py
```

Its raw output is `candidate_subset_30_current_results.json`. The baseline verifies
the expected retrieved corpus entry, matching the correctness scope of the existing
worst-case validator; it does not verify every wrong entry in the shortlist for
false-positive attribution analysis.

## Tier 1 release self-check

Run the real-release evaluation with:

```text
PYTHONPATH=. .venv/bin/python -u scripts/validate_tier1_releases.py
```

Tier 1 checks whether each labeled source path is shipped in the npm tarball in its
original language. A TypeScript label is scorable only when the release contains the
labeled TypeScript source; a compiled JavaScript artifact does not satisfy it.
Compiled-only releases are reported as `source_absent` and excluded from detector
accuracy metrics.

The validator logs and records whether each target was `source_present` or
`source_absent`. Tier 1 and Tier 2 both use same-language evidence: TypeScript
candidates are evaluated against TypeScript corpus entries, and JavaScript
candidates against JavaScript entries. Results use schema
`tier1_release_selfcheck_v3`.
