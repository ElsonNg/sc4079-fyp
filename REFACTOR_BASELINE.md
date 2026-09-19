# Refactor baseline

Captured on 2026-09-19 before production changes, at commit
`b4925e7c8bff88834d98f3e3da0e4617643192ab`.

## Validation

The complete test suite passed: **323 passed in 87.12 seconds**, with no failures,
errors or skips. Command, from the repository root in PowerShell:

```powershell
$env:HF_HUB_OFFLINE='1'
$env:TRANSFORMERS_OFFLINE='1'
.\.venv\Scripts\python.exe -m pytest -q --tb=short --junitxml=.provtrail/refactor-baseline/pytest.xml
```

An initial run without offline mode was interrupted after little progress. The
completed run includes tests marked `slow`; none were deselected.

Environment: Windows build 26200, Python 3.11.3, pytest 9.1.1, Pydantic 2.13.4,
NumPy 2.4.6, sentence-transformers 6.0.0, torch 2.13.0+cu130 and faiss-cpu 1.15.0.
CUDA is available; the embedding implementation forces FP32. The locally available
Qwen3-Embedding-0.6B revision is
`97b0c614be4d77ee51c0cef4e5f07c00f9eb65b3`.

## CLI and incremental scan

A source fixture uses the corpus vulnerable `busy` method for
`GHSA-35p6-xmwp-9g52`, wrapped in a class so it is valid standalone JavaScript.
The real CLI scanned it against the existing 301-entry corpus and retrieval index.

| Observation | First scan | Second scan |
|---|---|---|
| Functions scanned | 1 | 0 |
| Functions reused | 0 | 1 |
| Finding | automatic_vulnerability | automatic_vulnerability |
| Hash match types | abstracted, exact | abstracted, exact |
| CLI exit code | 1 | 1 |
| JSON and HTML generated | Yes | Yes |

Both successful invocations used `PYTHONIOENCODING=utf-8` and the offline settings
above. HTML generation was verified; browser rendering was not inspected.

An earlier invocation using the default CP1252 stdout encoding raised
`UnicodeEncodeError` when printing the Unicode console summary, after saving the
JSON/HTML artifacts. This is a pre-existing portability issue, not a refactor
regression. Its exit code must not be mistaken for a successful flagged scan.
No production fix has been made.

A separate synthetic detector fixture captures the CLI/report/cache boundary with
no credible lineage. Its first scan computes one function and its second reuses
one; both exit 0. It is not evidence of detector accuracy.

## Historical evaluation references

Use these as the initial historical comparison pair, pending fresh reproduction:

| Result file under `eval/` | Tier 1: `tier1_production_fp32_results.json` | Tier 2: `llm_transformed_expanded_fp32_results.json` |
|---|---|---|
| Recorded date (UTC) | 2026-09-17 | 2026-09-17 |
| Schema | evaluation_results_v4 | evaluation_results_v5 |
| Cohort rows | 600 | 600 (300 positive, 300 negative) |
| Recall@10 | 0.98 | 0.99 |
| MRR | 0.9749166667 | 0.8669484127 |
| True positives / false negatives | 288 / 0 | 244 / 0 |
| Patched false positives / true negatives | 13 / 274 | 21 / 152 |
| Vulnerable / patched abstentions | 7 / 7 | 56 / 127 |
| Patched false-positive rate | 0.0452961672 | 0.1213872832 |
| Abstention rate | 0.0237691002 | 0.305 |

Both record `experimental_local_correspondence=false` and metric methodology
`interim_report_chapter5_v1`. Tier 1 records `target_functions_only=true`, uses
`tier1_curated_labels.jsonl`, and scores 589 of the 600 rows. Tier 2 uses
`llm_transformed_expanded_positive.jsonl` and
`llm_transformed_expanded_negative.jsonl`, with `corpus_from_fixtures=false` and
edit-side/margin thresholds 0.90/0.10.

The filename FP32 designation agrees with the current embedding implementation,
but these result files do not record the complete device, model revision, index
fingerprint or detector configuration. Do not claim they were produced in the
current environment. Full evaluation reruns have not been performed in this
baseline capture; per-candidate equivalence remains a gate for subsequent phases.
The legacy Tier 1 release self-check and experimental fallback results are not
interchangeable with this pair.

## Contracts to preserve

| Contract | Current source and required invariant |
|---|---|
| Detection models | `pipeline/models/regions.py`: model fields, defaults, literals, validation and nested JSON schemas |
| Configuration | `RegionDetectorConfig`, `RegionVerifierConfig`: frozen dataclasses, defaults and `fingerprint_config()` output |
| Scan reports | `ScanSummary.to_dict()`: `provtrail_scan_v5`, public finding fields and removal of top-level finding source |
| Incremental state | `ScanState.to_dict()`: schema version 1; target/corpus/config identity, Merkle snapshot, functions and result cache |
| Cached results | `RESULT_CACHE_SCHEMA_VERSION=25`; rebind candidate identifiers without changing verdicts |
| Review explanations | Cache schema 1; prompt version `advisory-relevance-v5-full-function-region`; content-addressed reuse |
| Corpus records | `CorpusEntry` schema, provenance fields and source hashes |
| Retrieval storage | FAISS data and JSON metadata including model ID, pairs, indexed pair IDs/sides and fingerprint |
| Console/report behavior | Report classification, attention counts, exit codes and JSON/HTML paths |

Current corpus fingerprint:
`b35cb71940144b6b3105de86207a03bc4291365c4bdfdef9280377251be7f494`.

Current region index fingerprint:
`5bcd533312ea18235cb1c42f6f0db589873b202f903db1774ba2a0182e944970`.

## Evidence location and limitations

Local evidence is isolated under `.provtrail/refactor-baseline/` (Git-ignored):

- `environment.json`, `runtime.json`: environment, dependency versions, initial
  Git status, model revision, corpus/index identities;
- `artifact-hashes.json`: SHA-256 hashes of the selected result inputs, corpus DB
  and retrieval files; result hashes are in `historical-evaluations.json`;
- `model-schemas.json`, `detector-defaults.json`: pre-move model/config contracts;
- `pytest.log`, `pytest.xml`: complete test result;
- `real-scan-{1,2}.json`, `.html`, `.stdout.txt`, `.stderr.txt`, `.exit.txt`:
  real scan evidence;
- `exact-source-entry.json` and `exact-project/`: source fixture and scan state;
- `capture.py` and `scan-{1,2}.*`: synthetic boundary fixture and capture helper.

These local artifacts must be retained during the refactor; they are not included
by committing this document. The original worktree contained an untracked refactor
plan, comparison outputs and `scripts/run_jscpd_pilot.py`; their exact inventory
is in `environment.json`. No existing evaluation results were regenerated.

The safety baseline is recorded, with historical evaluation provenance explicitly
limited. Phase 1 was subsequently approved. Before extraction, six representative
payloads and hashes of all twelve region model schemas were captured in
`tests/fixtures/region_model_contracts.json`, including patched, uncertain,
lineage-only and nested evidence cases.

## Phase 1 validation

The twelve region models now live in six cohesive modules, with `regions.py` as
the compatibility facade. Detector/verifier configuration and shared defaults
live in `pipeline/detection/config.py`. No model fields, defaults, thresholds or
algorithm bodies changed. The extracted model class ASTs match the originals.

- Focused model, detector, cache and report checks: **94 passed**.
- Full suite, including model-dependent tests: **350 passed in 119.89 seconds**.
- Pre-refactor schemas, six saved payloads, configuration defaults/fingerprint,
  frozen dataclasses and old/new import identities all match.
- Canonical model/configuration imports load no controller modules or ML runtimes.
- Fresh CLI detection and reuse of the original scan cache both produce findings
  identical to `real-scan-1.json`, with exit code 1 and JSON/HTML output.

The full-suite command is the baseline command with output redirected to
`phase1-pytest.log` and JUnit output set to `phase1-pytest.xml` in the same local
evidence directory. CLI comparisons are in `phase1-cli-comparison.json` with
`phase1-fresh.*` and `phase1-reused.*` artifacts.

Fresh Tier 2 runs use the same expanded inputs, corpus and index, with output
isolated as `tier2-before.json` and `tier2-after.json`. The original run loaded its
detector before code extraction. Both runs completed all 600 candidates. Every
candidate record, including retrieval ranks and boundary verification evidence,
matches exactly. The entire result matches after removing only
`generated_at_utc`; no floating-point tolerance was needed. The fresh pre-refactor
summary also matches the historical FP32 summary. The comparison is saved in
`phase1-tier2-comparison.json`; `compare_tier2.py` reproduces it.

Tier 2 command, with the baseline offline settings plus `PYTHONPATH=.` and
`PYTHONIOENCODING=utf-8`:

```powershell
.\.venv\Scripts\python.exe -u scripts/validate_llm_transformed_subset.py --positive eval/llm_transformed_expanded_positive.jsonl --negative eval/llm_transformed_expanded_negative.jsonl --output .provtrail/refactor-baseline/tier2-after.json
```

The pre-refactor run used the same command with `tier2-before.json` as its output.
Normalized result SHA-256:
`df15152da8b61b5d517b013b933898d09808b87d26b3019607a20e4778457e30`.

The fresh Tier 1 attempt could not fetch uncached GitHub source trees: the network
proxy refused connections to `api.github.com`. It was stopped after repeated
source-fetch failures. `tier1-before.log` preserves the evidence. Tier 1 equivalence
remains unverified; no historical results were overwritten and this limitation is
not a passing evaluation gate. Resolve it before declaring all phase gates met.

## Approved grouped-model extension

The user subsequently approved grouping the large models and requested brief,
single-line comments above their properties, with examples where useful.

| Model | Original top-level fields | Grouped top-level fields |
|---|---:|---:|
| `VulnerableRegionPair` | 30 | 9 |
| `VulnerabilityState` | 50 | 10 |
| `RegionVerificationEvidence` | 36 | 7 |
| `HashMatch` | 23 | 7 |

Pair and hash models now compose shared advisory metadata and source references
from `pipeline/models/provenance.py`. `PackageAdvisory` retains the region pair's
required package and npm default. State groups boundary identity, scores, edit
evidence, gates, fallbacks and support. Region verification uses the same
`ReferenceSideEvidence` type for vulnerable and patched measurements.

Internal callers use grouped attributes such as `pair.advisory.cve_id`,
`match.origin.file_path`, `state.edit.margin` and `evidence.vulnerable.structural`.
`pipeline/models/records.py` contains the flat-record mappings and explicit
`from_record()`/`to_record()` conversions. The result model applies these at the
report/cache boundary; corpus index writers serialize region pairs with
`to_record()`. Old import paths remain valid. Internal constructors and JSON
schemas intentionally reflect the grouped structure; saved JSON stays flat.

Property comments distinguish active containment from optional correspondence
and alignment. The original 600-candidate Tier 2 run records 2,109 boundary-level
containment attempts and 183 uses. The saved experimental correspondence run
records 516 attempts and 2 uses; these are historical boundary counts, not unique
candidates or a fresh experiment. Both alignment options and local correspondence
remain disabled by default. No fallback was removed or enabled by this refactor.

The frozen contract fixture now includes a hash match generated from the original
commit's model. Grouped-update tests exercise all four models against flat records,
and detector tests cover correspondence disabled, enabled/resolved and
enabled/unresolved. The final full suite passed **363 tests in 88.34 seconds**.
Fresh and cached real CLI findings both match the original baseline exactly;
both exit 1 and generate JSON/HTML. Logs are `grouped-verified-pytest.log` and
`grouped-verified-pytest.xml`; CLI comparisons are in `grouped-cli-comparison.json`.

The complete detection run processed all 600 Tier 2 candidates. Its comparison
exposed an evaluation adapter that still read hash identity from flat attributes:
all verdicts matched, but 25 abstracted hash hits were omitted from the metrics.
The hash, ranked-retrieval, origin-stage and clone-comparison helpers now read
grouped identity while retaining support for existing flat records. Six additional
tests cover model objects, nested dictionaries and flat dictionaries.

After that fix, `replay_hash_metrics.py` reran actual corpus hash lookups and the
corrected metric helper for all 600 inputs, retaining the completed run's unchanged
detection evidence. `tier2-grouped-verified.json` and
`grouped-tier2-verified-comparison.json` record the result: every candidate record
and summary matches the original, excluding only the generation timestamp. The
normalized SHA-256 is again
`df15152da8b61b5d517b013b933898d09808b87d26b3019607a20e4778457e30`.
The initial mismatching output is retained as `tier2-grouped.json` for audit.
No corpus, index, existing cohort or historical result was changed. The separate
Tier 1 network-access limitation remains outstanding.

## Model audit: metadata consolidation and derived state

The user approved audit phases 2 and 3 after removing the unused definitions.
These are model-audit phases, not the CLI/package migration phases in the main
plan. No CLI handler extraction or package relocation was performed.

`shared/metadata.py` now owns advisory and source contracts without importing
corpus or pipeline modules. Previous provenance/CWE imports remain available.
`CorpusEntry`, `RetrievalMatch`, `RegionRetrievalMatch` and `VerificationResult`
compose `advisory` and `origin`; `shared/records.py` accepts legacy flat records
and grouped input, and serializes to the existing flat format. The corpus's
required package/ecosystem fields and each projection's original metadata subset
are preserved.

| Model | Previous top-level fields | Current top-level fields |
|---|---:|---:|
| `CorpusEntry` | 32 | 16 |
| `RetrievalMatch` | 14 | 3 |
| `RegionRetrievalMatch` | 27 | 12 |
| `VerificationResult` | 15 | 9 |

`VerificationGates.boundary_rejected`, `BoundaryEditEvidence.contrastive_used`
and `RegionAggregate.support_count` are computed from the accepted gate, selected
strategy and candidate IDs. They remain serialized. Contradictory legacy derived
values are normalized to their source fields, including synthetic fixtures that
previously specified support counts without candidate IDs.

Validation completed:

- **370 tests passed in 31.29 seconds**, including model-dependent tests, with
  Hugging Face offline settings. Explicitly targeted `tests/` to exclude external
  evaluation tool installations. Artifacts: `phase23-pytest.log` and
  `phase23-pytest.xml` in `.provtrail/refactor-baseline/`.
- Four flat metadata fixtures were captured from the original model definitions;
  tests cover both input forms, required metadata, independent defaults and
  derived-value consistency. The final focused rerun passed 38 tests.
- All **301 corpus entries** serialize identically to the snapshot taken before
  this extension (`metadata-before.json`).
- Real CLI scans, both fresh and reused, produce findings identical to
  `grouped-fresh.json`, exit 1, and generate JSON/HTML. Results are recorded in
  `phase23-cli-comparison.json` and `phase23-{fresh,reused}.*`.
- All 129 project Python files parsed successfully.

No fresh full Tier 2 evaluation was run for this extension. The earlier Tier 2
comparison remains historical evidence; the Tier 1 network limitation is unchanged.
