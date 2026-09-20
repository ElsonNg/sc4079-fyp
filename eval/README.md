# Evaluation commands

Run commands from the repository root. The Python modules under `eval/` own the
implementations. Matching files under `scripts/` remain entry points for older
commands. All defaults write to the top-level `eval/` directory.
Set `PROVTRAIL_DATA_DIR=corpus/data` when running from the repository root to
reuse the existing embedding indexes. Tier 1 release checks fetch GitHub source
trees and use `GITHUB_TOKEN` from the environment or the working directory's
`.env` file.

| Evaluation | Build input | Run and score | Default result |
| --- | --- | --- | --- |
| Tier 1 release check | `python -m eval.tier1.build_tier1_targets` | `python -m eval.tier1.validate_tier1_releases` | `tier1_release_results.json` |
| Tier 2 transformed code | `python -m eval.tier2.generate_llm_transformed_subset --expanded` | `python -m eval.tier2.validate_llm_transformed_subset --positive eval/llm_transformed_expanded_positive.jsonl --negative eval/llm_transformed_expanded_negative.jsonl --output eval/llm_transformed_expanded_results.json` | `llm_transformed_expanded_results.json` |
| Retrieval ablation | `python -m eval.fixtures.generate_candidate_subset` and `python -m eval.fixtures.generate_negative_subset` | `python -m eval.ablation.run_retrieval_ablations` | `retrieval_ablation_results.json` |
| Decision ablation | Same 30 positive and 60 negative fixtures | `python -m eval.ablation.run_decision_ablations` | `decision_ablation_k5_evidence20_results.json` |
| Tool comparison | `python -m eval.comparison_benchmark.build_tool_comparison` | `python -m eval.comparison_benchmark.run_tool_comparison`, then `python -m eval.comparison_benchmark.score_tool_comparison --findings <normalized.jsonl>` | `comparison_summary.json` |

The saved `tier1_production_fp32_results.json` uses the curated label manifest:

```text
python -m eval.tier1.validate_tier1_releases --labels eval/tier1_curated_labels.jsonl --target-functions-only --max-functions 1 --output eval/tier1_production_fp32_results.json
```

Comparison tool installation is separate: run
`python -m eval.comparison_benchmark.bootstrap_comparison_tools` before running
the comparison if pinned tools are unavailable. `materialize_tool_comparison`
prepares source workspaces. `import_tier1_comparison` converts existing Tier 1
results into comparator findings without running another scan. The 50-case
comparison uses `build_tool_comparison --origins 50` and explicit `--cases`,
`--ground-truth`, `--tool-lock`, `--findings`, and `--output` paths ending in
`comparison_50_*`.

Saved `*_smoke`, `*_limit2`, `*_fallback`, `*_retry`, and `*_corrected` files are
historical checkpoints from individual experiments. Their exact old command
arguments and tool state are not fully recorded. They are retained for audit,
not presented as fresh results from the commands above.

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
python -m eval.fixtures.generate_candidate_subset
```

The generator verifies that every candidate differs from its vulnerable source and
is parseable by Tree-sitter JavaScript, including class-method snippets that need a
synthetic wrapper. This is a positive structural-clone fixture, not a runtime
semantic-equivalence proof and not a complete accuracy benchmark. A separate
patched/benign hard-negative set should be evaluated alongside it.

`candidate_subset_30_current_results.json` is a historical August 2026 result
from the retired whole-function retrieval and hierarchical verification pipeline.
It flagged 15 of 30 positive candidates and sent the other 15 to manual review.
The current scanner does not use this verification path, and Tier 1 and Tier 2
metrics do not consume this file. Run
`python -m eval.fixtures.validate_region_candidate_subset` to evaluate these
fixtures with the current AST-region detector.

## Tier 1 release self-check

Run the real-release evaluation with:

```text
python -m eval.tier1.validate_tier1_releases
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
python -m eval.tier2.generate_llm_transformed_subset --expanded
```

The expanded generator draws from every transformation-eligible corpus pair,
uses Type-3 and Type-4 variants where needed to match Tier 1's 300/300 class
balance, and writes each accepted record immediately to separate `*_expanded_*`
fixtures. Re-running the command resumes from those records without overwriting
the historical 145-sample Tier 2 fixture.

After generation completes, evaluate it with:

```text
python -m eval.tier2.validate_llm_transformed_subset \
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
