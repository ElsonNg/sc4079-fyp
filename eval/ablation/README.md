# Frozen Tier 1 / Tier 2 experiments

This workflow leaves scanner defaults and historical fixtures/results unchanged.
It evaluates **known-origin retrieval**: expected reference origins remain in the
searchable index. The seed-4079 30% tuning / 70% evaluation partition is a
**retrospective grouped split**, not a pristine holdout. The existing cohorts,
reference corpus and prior evaluations have already informed development.

Run commands from the repository root, using the repository virtual environment.
The local Ollama service must already contain the requested model tags; generation
and model review record the actual installed digests. Run generation and review
sequentially on a machine with limited GPU memory.

```powershell
.venv/Scripts/python.exe -m eval.tier2.cohort generate --output eval/frozen/tier2-v1
.venv/Scripts/python.exe -m eval.tier2.cohort validate --output eval/frozen/tier2-v1
.venv/Scripts/python.exe -m eval.tier2.adjudicate --input eval/frozen/tier2-v1 --decisions eval/frozen/source-adjudications-v1.jsonl --output eval/frozen/tier2-v2
$env:PROVTRAIL_EMBEDDING_DEVICE = 'cpu'
.venv/Scripts/python.exe -m eval.ablation.freeze --cohort eval/frozen/tier2-v2 --output eval/frozen/experiment-v2
```

Generation selects at most ten distinct origins per missing package, round-robin
by advisory in stable order. It does not filter out anchor-ineligible origins or
duplicate origins to meet quotas. Each origin has four tasks: requested Type 3
and Type 4 on vulnerable and patched sides. Three requests maximum per task;
the attempt journal supports interrupted-request accounting and resume. Reusing a
generation directory with changed origins, model digest or locked settings fails.
Original historical generation digests and attempts were not recorded and cannot
be recovered retroactively.

Validation checks candidate/source hashes, embedded source identity and parsing
in the declared language. Diagnostic anchors are recorded only as screening.
Package-specific Node litmus tests cover qs prototype assignment, lodash's
`safeGet`, minimist's prototype predicate, semver's length/exception guards and
moment's nested-comment regex boundary. They must distinguish both originals
before validating a candidate. Test failures/inconclusive results are quarantined.
The semver harness uses explicit dependency stubs; the moment test exercises the
changed regex semantics and does not assert a measured ReDoS bound.

For remaining cases, the validator uses an automated model review of the original
security delta and candidate's security state, with exact source quotations.
Conservative AST checks can establish preservation for simple syntax-preserving
rewrites, but cannot independently validate the original security label.
These are automated reviews, never human validation. Review
records identify the security delta, preservation reasoning, model digest, prompt
and settings. Unsupported or uncertain cases are excluded. A review's acceptance
is evidence, not universal semantic equivalence. Review the retained evidence for
research uses requiring stronger assurance.

The final `adjudicate` step produces a separate cohort version. Every provisionally
admitted model-reviewed origin requires a source-hash-bound, independently
documented automated audit of its extracted security delta. Missing decisions
fail instead of silently admitting cases. Incidental patch changes, bundled
module renumbering, and security claims depending on absent helper implementations
are quarantined. A conservative literal/regex screen additionally rejects model
admissions with changed literals that lack executable behavioural evidence. It is
a screen, not proof; equivalent rewrites may be excluded. Failed original reviews
and tests are never promoted. The provisional journals are preserved.
Every model-reviewed candidate that survives those checks additionally requires
an independent, candidate-hash-bound preservation review. Missing audits fail;
incorrect branches, stale identifiers, changed destructuring, or unsupported
operation-order changes quarantine the whole matched pair. Supporting helper
context must match the exact reference fix and is embedded in the audit record.

The supplied source adjudications apply only to these frozen original sources.
New origins require new documented decisions. The final cohort preserves model
clone-category proposals separately, confirming only mechanically established
Type 1/2 categories in this release. Other cases retain requested, unconfirmed
Type 3/4 categories even when their security-label evidence is accepted.

Acceptance is paired by reference origin and **requested** transformation type.
If either side fails, is duplicated, or is absent, both sides are quarantined.
`requested_clone_type`, `proposed_clone_type`, `reviewed_clone_type`, and `clone_type_status` deliberately
differ: a requested Type 4 can turn out to be Type 2, and executable label evidence
can leave clone classification unconfirmed. Do not report all generated cases as
confirmed Type 3/4. `attrition.json` and `attrition.md` give actual package coverage,
shortfalls, exclusions and generation failures; do not infer 22-package coverage.

The freeze includes hashes of copied reference database/index bytes, accepted
fixtures, quarantine, validation/review/attempt/adjudication records, split, source code, dependencies,
embedding model snapshot bytes, precision and resolved baseline configuration.
The model snapshot stays in the existing local Hugging Face cache; its absolute
paths and hashes are locked. The manifest is content-sealed and refuses overwrite.
Use a new experiment version for any change. The runner checks every frozen input
and loads only the frozen index; it never silently rebuilds an index or fetches a
different model. Moving this workspace/cache requires an explicit new freeze.

Tier 1 confirmation uses historical release target hashes that exactly match
available reference source. It does not substitute a nearby function for an
unavailable release target. Exclusions are written to `tier1-excluded.jsonl` and
still participate in grouping. Advisory aliases, shared repository/fix commits,
reference-source duplicates and candidate-source duplicates are joined
transitively across both tiers. The split balances package, label and tier
approximately without dividing groups; inspect actual counts in `split.json`.

Smoke verification (full detector, baseline plus a K=1 control):

```powershell
.venv/Scripts/python.exe -m eval.ablation.run_frozen --manifest eval/frozen/experiment-v2/manifest.json --sweep eval/ablation/smoke.json --split tuning --tier both --output eval/frozen/smoke-v1 --smoke-limit 8 --verify-direct-baseline
# Identical settings are required to resume:
.venv/Scripts/python.exe -m eval.ablation.run_frozen --manifest eval/frozen/experiment-v2/manifest.json --sweep eval/ablation/smoke.json --split tuning --tier both --output eval/frozen/smoke-v1 --smoke-limit 8 --verify-direct-baseline --resume
```

Smoke selection is deterministic and covers the available labels, declared
languages, requested transformation types, tiers, and hash/non-hash paths.
The IDs and coverage are persisted in `run-lock.json`. A limit too small to cover
those strata fails. Baseline verification compares the complete runner result
against direct detector execution on each identical candidate.
This small tuning smoke also exercises tradeoff and non-dominance exports; its
metrics are a wiring check, not a basis for choosing detector settings.

Prepared commands for the **deferred** full study (not run by this task):

```powershell
.venv/Scripts/python.exe -m eval.ablation.run_frozen --manifest eval/frozen/experiment-v2/manifest.json --sweep eval/ablation/sweep.json --split tuning --tier tier2 --output eval/frozen/tuning-tier2-v1
.venv/Scripts/python.exe -m eval.ablation.run_frozen --manifest eval/frozen/experiment-v2/manifest.json --sweep eval/ablation/sweep.json --split evaluation --tier tier2 --output eval/frozen/evaluation-tier2-v1
.venv/Scripts/python.exe -m eval.ablation.run_frozen --manifest eval/frozen/experiment-v2/manifest.json --sweep eval/ablation/sweep.json --split tuning --tier tier1 --output eval/frozen/tuning-tier1-v1
```

The predefined grid has 31 unique configurations. All non-varied settings stay
at the frozen Tier 2 baseline: K=10, verification budget=10, edit-side=0.90,
margin=0.10, structure/token=0.70 and retrieval threshold=0. Inactive support and
consensus controls cannot be swept. Each configuration reruns complete detection;
there is no reconstruction/reclassification of incomplete historical edit evidence.

Checkpoints bind the entire candidate, resolved configuration and sealed manifest,
and have their own integrity seal. Outputs are `cases.jsonl`, `summary.json`,
`summary.csv`, and `tables.md`. Metrics keep tiers separate and report numerator,
denominator, and rate. Retrieval before the verification budget, shortlist
survival, expected-fix visibility (matching hash, or retained lineage plus the
expected boundary state), correct-fix automatic detection, any wrong-fix attribution,
patched false positives, manual-review abstention, and measured detection runtime
are distinct. Hash and non-hash retrieval have separate denominators. A correct
and a wrong boundary may coexist; wrong attribution is still counted. Conditional
rates explicitly exclude abstentions and all-labelled rates are also exported.
Runtime excludes model/index setup and is sensitive to warm-up and system load.
Tuning outputs show non-dominated tradeoffs, never an automatically selected winner.

```powershell
.venv/Scripts/python.exe -m pytest tests/test_frozen_ablation.py tests/test_candidate_gate.py tests/test_candidate_language.py tests/test_llm_transform.py tests/test_evaluation_metrics.py tests/test_tier1_targets.py -q
```
