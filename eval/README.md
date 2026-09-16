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

Tier 1 fetches the eligible same-language source tree from the package repository at
the exact vulnerable or fixed release commit. TypeScript labels therefore remain
TypeScript and JavaScript labels remain JavaScript; compiled npm artifacts are not
used for the primary metric.

The validator scores the labelled evidence target for the primary metrics and reports
unrelated detections from the rest of the package as background noise. Tier 1 and
Tier 2 both use same-language evidence: TypeScript
candidates are evaluated against TypeScript corpus entries, and JavaScript
candidates against JavaScript entries. Results use schema
`evaluation_results_v4`, including ranked retrieval metrics, verification metrics,
abstention rate, and optional LLM metrics.

The metric definitions follow Chapter 5 of the interim report. Primary lineage
Recall@K and MRR include expected-lineage exact or abstracted hash hits at rank 1;
missing lineages remain in the denominator and contribute zero reciprocal rank.
`non_hash_retrieval` reports the aggregate retrieval path separately. Vulnerable
recall is `TP / (TP + FN)`, patched false-positive rate is `FP / (FP + TN)`, and
abstentions are excluded from those two denominators and reported independently.

Tier 1 limits background scanning to 1,000 functions per package release by
default, while always retaining the labelled target file. Use
`--max-functions 0` for an unlimited scan.

## Expanded Tier 2

Build the balanced 600-sample Tier 2 cohort (300 vulnerability-preserving and
300 patched transformations) with:

```text
PYTHONPATH=. .venv/bin/python -u scripts/generate_llm_transformed_subset.py --expanded
```

The expanded generator draws from every transformation-eligible corpus pair,
uses Type-3 and Type-4 variants where needed to match Tier 1's 300/300 class
balance, and writes each accepted record immediately to separate `*_expanded_*`
fixtures. Re-running the command resumes from those records without overwriting
the historical 145-sample Tier 2 fixture.

After generation completes, evaluate it with:

```text
PYTHONPATH=. .venv/bin/python -u scripts/validate_llm_transformed_subset.py \
  --positive eval/llm_transformed_expanded_positive.jsonl \
  --negative eval/llm_transformed_expanded_negative.jsonl \
  --output eval/llm_transformed_expanded_results.json
```

Source downloads use eight workers by default and skip non-target background files
larger than 1 MB; labelled target files are always downloaded. Tune these with
`--fetch-workers` and `--max-background-source-bytes` (`0` disables the byte cap).
GitHub primary and secondary rate limits pause the worker pool until the advertised
retry/reset time, and completed targets continue to be saved in the output's
checkpoint file for automatic resume.
