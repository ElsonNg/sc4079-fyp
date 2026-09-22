# Frozen benchmark delivery

Use **experiment-v2/manifest.json** with **tier2-v2/accepted.jsonl**. Full ablations have not been run. Commands and methodology are in [the runner documentation](../ablation/README.md).

## Cohort

Generation selected 51 distinct origins across the eight requested expansion packages and produced 188 candidates in 259 attempts. Sixteen generation tasks exhausted the three-attempt allowance. Validation examined those candidates and the 600 historical cases.

Final admission retained **60 cases (30 vulnerable/patched pairs)**: 38 new cases and 22 historical cases, covering **10 packages**. The remaining 728 input cases are quarantined. This is a conservative admitted subset of the expanded candidate pool, not a 600-case-plus accepted benchmark and not 22-package coverage.

| Expansion package | Selected origins | Accepted cases |
|---|---:|---:|
| axios | 10 | 2 |
| lodash | 4 | 2 |
| minimist | 4 | 0 |
| moment | 4 | 4 |
| nodemailer | 9 | 0 |
| qs | 9 | 24 |
| semver | 1 | 4 |
| undici | 10 | 2 |

Historical admissions cover parse-server (10), nuxt (4), liquidjs (4), and vite (4). See [attrition.md](tier2-v2/attrition.md), `attrition.json`, `validation.jsonl`, and `source-adjudications.jsonl` for exact evidence and exclusions. Rejection reasons can overlap and their frequencies count recorded reason occurrences, not mutually exclusive attrition bins.

Security-label evidence consists of 34 package-specific executable litmus admissions and 26 admissions with automated source-and-patch review plus an independent candidate-preservation audit. No human validation is claimed. The requested categories are Type 3 (36) and Type 4 (24); 58 clone classifications remain unconfirmed and two are mechanically confirmed Type 1 formatting changes. Do not present these counts as confirmed Type 3/4 coverage. Historical generator weight digests were unavailable and remain explicitly unknown.

## Freeze and split

The manifest seals the 301-entry reference database, existing derived index, accepted and quarantined fixtures, provenance/validation/audit records, local FP32 embedding weights, code, dependencies and resolved detector baseline. Expected origins remain searchable: this measures known-origin retrieval.

Seed 4079 groups advisory aliases, shared fixes and duplicate sources across both tiers. The partition is retrospective and historically exposed, not a pristine holdout. Its approximate 30/70 target never divides a group.

| Eligible cohort | Tuning | Evaluation |
|---|---:|---:|
| Tier 1 target confirmation | 166 | 416 |
| Tier 2 | 16 | 44 |

Eighteen unavailable Tier 1 targets are excluded from execution but retained as grouping bridges. The split file also reports counts including them. `experiment-v1` is a preserved, superseded freeze from the earlier package-only balancing rule; it is not the delivered experiment and its old code hashes intentionally reject the current revised code. Use v2.

## Verification

- 69 relevant tests passed, covering selection, pairing/quarantine, generation/review resume, grouping, sparse-package balancing, manifest/index mismatch refusal, sweep expansion, checkpoints, evidence admission and denominators.
- The eight-case tuning smoke ran two complete detector configurations (baseline and K=1), yielding 16 case checkpoints. All eight baseline outputs matched direct detector execution exactly.
- Resume reused all 16 checkpoints with identical hashes and modification times. The active manifest passed final integrity verification; the machine-readable verification record is [verification.json](verification.json).
- Coverage includes both labels, JavaScript/TypeScript, both requested categories, both tiers and hash/non-hash paths. Tier 1 contributes one patched target in this wiring smoke; it is not a Tier 1 recall estimate.
- JSONL, JSON, CSV, Markdown, tuning tradeoffs and non-dominated sets are in [smoke-v1](smoke-v1/tables.md). These small-sample outputs are for verification, not configuration selection. Correct and additional wrong-origin attributions can coexist; the smoke reports both rather than hiding the latter.

Scanner defaults and pre-existing workspace edits were preserved. No full tuning or evaluation ablation study was executed.
