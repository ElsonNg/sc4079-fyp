# Facts and Figures: Vulnerable Clone Detection

This is the living evidence ledger for the vulnerable-code-clone detector. It records
what the current methodology actually does, what has been measured, what is only
inferred from the implementation, and why a later methodology change was justified.

Keep this document factual. Do not replace an old result when the methodology changes;
append a new snapshot and link the decision to the supporting evidence.

Related documents:

- [Project conventions](conventions.md)
- [Pivot plan](PIVOT.md)

## 1. Snapshot metadata

| Field | Current snapshot |
|---|---|
| Snapshot date | 2026-08-16 |
| Source commit inspected | ffa3b60 |
| Corpus database | corpus/data/corpus.db |
| Default embedding model | qwen3-embedding-0.6b |
| Default retrieval threshold | 0.7 |
| Default verification margin | 0.1 |
| Baseline status | Pre-AST-region pivot |
| Measurement status | Partial; full end-to-end metrics are not yet recorded |

The repository had local working-tree changes when this snapshot was inspected. Every
future result must record both the source commit and whether it was run against a
clean tree or a modified working tree.

## 2. Current corpus facts

These figures are direct counts from the persisted SQLite corpus at the snapshot date.

| Measure | Value | Interpretation |
|---|---:|---|
| Corpus entries | 131 | Function-level vulnerable/patched records |
| Distinct advisories | 22 | GHSA-level advisory coverage |
| Distinct packages | 2 | axios and express only |
| Distinct repositories | 2 | Narrow repository diversity |
| OSV-confirmed entries | 110 / 131 | 84.0% confirmed; 21 are unconfirmed |
| Anonymous-function entries | 18 / 131 | 13.7% have no stored function name |
| Entries over 4,000 characters on either side | 33 / 131 | 25.2% are outside the small-function validation cutoff |
| axios entries | 128 | 97.7% of the corpus |
| express entries | 3 | 2.3% of the corpus |

These counts support the conclusion that the current corpus is useful for an axios /
express pilot but does not support broad claims about JavaScript-ecosystem detection.

## 3. Current test and evaluation facts

### Automated tests

The test suite currently contains 86 collected tests:

| Test tier | Result at snapshot |
|---|---|
| Fast, non-slow tests | 63 passed |
| Slow real-model/FAISS tests | 23 collected; not run for this snapshot |
| Full suite result | Not recorded |

The fast test result demonstrates deterministic mechanics, not detector accuracy. Slow
tests must be run separately because they load real embedding models and FAISS.

Commands:

~~~text
PYTHONPATH=. .venv/bin/python -m pytest -m "not slow"
PYTHONPATH=. .venv/bin/python -m pytest -m slow
PYTHONPATH=. .venv/bin/python -m pytest
~~~

### Existing validation fixtures

The repository contains:

- a fixed-sample end-to-end self-anchor validator;
- a hand-authored Type-2/3 clone validator;
- alignment, hierarchy, and verification smoke scripts;
- unit and slow integration tests for hashing, retrieval, alignment, hierarchy, and
  verification.

The hand-authored worst-case validator defines 13 unique vulnerability patterns
represented by 19 selected corpus entries. It evaluates vulnerable and patched
candidates, so a complete run produces 38 candidate cases. Its results must be treated
as a pilot, not as a statistically powered benchmark, because the clones were authored
by the same developer who designed the verifier.

No accuracy result from validate_e2e.py or validate_worst_case.py is claimed in this
snapshot until the scripts have been run and their output recorded below.

### Candidate subset fixture

On 2026-08-16, a reproducible positive-only fixture was generated at
`eval/candidate_subset_30.jsonl`:

| Measure | Value |
|---|---:|
| Candidate records | 30 |
| Distinct corpus entries | 22 |
| Transformation families | 8 |
| Distinct CVE IDs | 11 |
| OSV-confirmed records | 17 / 30 |
| Expected status | Flagged for every record |
| Structural validation | 30 / 30 parseable |

This fixture establishes coverage for deterministic structural clone generation; it
does not establish detector precision, recall, or runtime semantic equivalence. It
must be paired with patched/benign hard negatives before accuracy claims are made.

## 4. Methodology facts and evidence

The following are implementation facts, followed by their practical implication. An
implication is not a measured error rate unless a result is recorded in Section 6.

| ID | Implementation fact | Evidence | Practical risk | Confidence |
|---|---|---|---|---|
| F-001 | Hashing operates on complete functions and excludes abstracted bodies shorter than 50 characters. | pipeline/controller/hashing.py | Short or partial clones cannot use the hash path. | High |
| F-002 | Retrieval indexes only vulnerable whole-function entries. | pipeline/controller/retrieval.py | A vulnerable slice inside a large or refactored function may not retrieve. | High |
| F-003 | Retrieval uses a fixed 2,048-token maximum sequence length. | pipeline/controller/embedding.py | Later vulnerability-relevant code in long functions may be omitted from the embedding. | High |
| F-004 | The default retrieval threshold is 0.7 and is not backed by a recorded held-out calibration. | pipeline/controller/retrieval.py | Recall and false-positive behavior at the threshold are unknown. | High |
| F-005 | Verification margin is 0.1 and is explicitly described in source comments as a placeholder. | pipeline/controller/verification.py | Flagged, cleared, and manual-review rates are not yet statistically justified. | High |
| F-006 | Pure insertion/deletion cases may compare a whole-function score against a diagnostic-line score. | pipeline/controller/verification.py | The vulnerable-minus-patched score can mix non-equivalent score scales. | High |
| F-007 | The hierarchical verifier is order-preserving and supports only bounded span merges. | pipeline/controller/alignment.py and hierarchy.py | Reordering, extraction/inlining, and larger rewrites can reduce correspondence. | High |
| F-008 | The current parser and corpus extractor target JavaScript extensions: .js, .jsx, .mjs, and .cjs. | corpus/controller/extraction.py | TypeScript and other ecosystem sources are not represented by this path. | High |
| F-009 | Commit extraction uses production-file and changed-line limits plus heuristic function pairing. | corpus/controller/extraction.py | Legitimate fixes can be excluded or incorrectly paired before detection begins. | Medium |
| F-010 | The persisted retrieval fingerprint is based on corpus identity keys, not function contents. | pipeline/controller/retrieval.py | Source changes with unchanged identity can leave stale embeddings. | High |
| F-011 | The corpus contains duplicated vulnerable code across multiple advisories. | scripts/validate_worst_case.py and corpus/data/corpus.db | Retrieval may identify code lineage without uniquely identifying one CVE. | High |
| F-012 | The current validation set is dominated by self-anchors and hand-authored clones. | scripts/validate_e2e.py and scripts/validate_worst_case.py | Reported success may not generalize to naturally occurring clones. | High |

## 5. What is known versus unknown

### Established by direct measurement

- The persisted corpus has 131 entries across two packages and two repositories.
- 110 entries are marked OSV-confirmed.
- 33 entries exceed the small-function validation cutoff.
- 18 entries have no function name.
- 63 fast automated tests passed in the recorded run.
- The repository defines a 13-pattern hand-authored clone pilot, but no result from
  that pilot is recorded yet.
- The 30-case positive candidate fixture reached the correct corpus entry at Recall@5
  for 30/30 cases and at Recall@1 for 23/30 cases.
- On that same positive fixture, current verification flagged 15/30 and returned
  manual_review for 15/30; no candidate was cleared.

### Established by source inspection

- Retrieval is whole-function and vulnerable-side only.
- Candidate verification compares the candidate to vulnerable and patched references.
- Retrieval and verification thresholds are not fully calibrated.
- Long-function embedding truncation is a known limitation.
- The corpus extractor has JavaScript-only and heuristic-pairing constraints.
- The current index freshness check does not include source contents.

### Not yet established

- End-to-end precision and recall on advisory-disjoint data.
- Retrieval Recall@1, Recall@5, and Recall@10 for natural clones.
- False-positive rate on same-package hard negatives.
- False-negative rate for partial, reordered, extracted, and inlined clones.
- Whether the current verifier’s manual-review bucket is appropriately calibrated.
- Whether the AST-region pivot improves recall without materially reducing precision.
- Whether local alignment is still needed after region retrieval and structural checks.

Do not use a source-inspection fact as if it were a measured performance result.

## 6. Baseline results register

Append one row for every reproducible evaluation run. Keep the raw terminal output
or artifact path with the experiment record.

| Run ID | Date | Code state | Corpus/split | Cases | Hash FP | R@1 | R@5 | R@10 | Threshold misses | Verification correct | Manual review | E2E correct | Notes |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| BASE-000 | 2026-08-16 | ffa3b60 + local changes | Not run | — | — | — | — | — | — | — | — | — | Initial evidence ledger; do not treat as accuracy result |
| BASE-001-CAND30 | 2026-08-16 | af74f82 + local changes | `candidate_subset_30.jsonl`; 22 corpus entries / 11 CVEs; positive-only | 30 | 1 abstracted hash match* | 23/30 (76.7%) | 30/30 (100.0%) | 30/30 (100.0%) | 0/30 | 15/30 flagged | 15/30 | 15/30 | Qwen3-Embedding-0.6B; k=5; threshold=0.7; fresh 131-entry index; raw artifact linked below |

\*The one abstracted hash match is not a false positive for this positive clone
fixture; it is a renamed/reformatted clone that reached the hash stage. The row is
retained here because the existing register has a hash column, but it must not be
interpreted as a precision measurement.

### BASE-001-CAND30 detailed result

Raw per-candidate output: [candidate_subset_30_current_results.json](../eval/candidate_subset_30_current_results.json).

| Stage/result | Figure |
|---|---:|
| Candidates | 30 |
| Corpus entries searched | 131 |
| Hash matches | 1 / 30 (3.3%), abstracted only |
| Correct entry Recall@1 | 23 / 30 (76.7%) |
| Correct entry Recall@5 | 30 / 30 (100.0%) |
| Correct entry Recall@10 | 30 / 30 (100.0%) |
| Correct entry reached default shortlist (k=5, threshold=0.7) | 30 / 30 (100.0%) |
| Isolated verification flagged | 15 / 30 (50.0%) |
| Isolated verification manual review | 15 / 30 (50.0%) |
| Isolated verification cleared | 0 / 30 (0.0%) |
| End-to-end correct-entry flagged | 15 / 30 (50.0%) |
| End-to-end correct-entry manual review | 15 / 30 (50.0%) |
| End-to-end correct-entry not retrieved | 0 / 30 (0.0%) |

The 15 manual-review cases were C02, C04, C06, C10, C12, C13, C14, C16, C17,
C19, C20, C24, C26, C29, and C30. Verification scores ranged from -0.027 to
0.691; the 15 flagged cases were at or above the current +0.1 margin, while all
manual-review cases were below it. This is a measured positive-set result, not a
precision or generalization result: there were no benign or patched candidates in
this run.

By transformation family, the flagged/manual-review counts were:

| Transformation family | Flagged | Manual review | Total |
|---|---:|---:|---:|
| `alpha_rename+block_rewrite` | 1 | 0 | 1 |
| `alpha_rename+boolean_expansion` | 0 | 1 | 1 |
| `alpha_rename+dead_branch` | 5 | 6 | 11 |
| `alpha_rename+reformat` | 3 | 2 | 5 |
| `alpha_rename+return_split` | 5 | 4 | 9 |
| `alpha_rename+statement_reorder` | 0 | 1 | 1 |
| `alpha_rename+ternary_expansion` | 0 | 1 | 1 |
| `dead_branch` | 1 | 0 | 1 |
| **Total** | **15** | **15** | **30** |

This baseline indicates that retrieval was not the limiting stage on this fixture:
all 30 correct corpus entries reached the default shortlist, while verification
abstained on half of the known positives. The result supports calibrating or
replacing the current line/diagnostic verification score, while preserving the
distinction between a retrieval miss and a verification manual-review outcome.

Recommended first baseline runs:

~~~text
PYTHONPATH=. .venv/bin/python scripts/validate_e2e.py
PYTHONPATH=. .venv/bin/python scripts/validate_worst_case.py --mode=validate
PYTHONPATH=. .venv/bin/python scripts/validate_worst_case.py --mode=clone
~~~

For each run, record the complete stdout, model ID, corpus size, selection rules, and
whether the run used a clean or modified working tree.

## 7. Failure ledger

Use this table to track observed failures, not hypothetical risks. Add a row only when
a failure has a reproducible case or a documented source-level defect.

| Failure ID | First observed | Stage | Reproduction | Observed behavior | Impact | Root cause | Fixed by | Status |
|---|---|---|---|---|---|---|---|---|
| FL-000 | 2026-08-16 | Evaluation | Initial snapshot `BASE-000` | No baseline result was recorded | Accuracy was not quantifiable at the initial snapshot | Baseline scripts had not yet been run | `BASE-001-CAND30` | Superseded |
| FL-001 | Existing source note | Retrieval | Long axios functions | 2,048-token cap can make later revisions tie | Wrong or ambiguous ranking risk | Whole-function truncation | AST-region/windowed retrieval | Known, unmeasured |
| FL-002 | Existing source note | Verification | Pure insertion/deletion fix | One side can use whole-function fallback while the other uses diagnostic-line scores | Threshold comparison may be unstable | Non-equivalent score scales | Calibrated region-level scoring | Known, unmeasured |
| FL-003 | Existing source note | Corpus | TypeScript/unsupported syntax | Function extraction may skip or misparse units | Silent coverage loss | JavaScript-only parser/extractor | Parser coverage expansion and explicit reporting | Known |
| FL-004 | Existing source note | Retrieval | Same identity, changed source | Existing index may be considered fresh | Stale retrieval evidence | Identity-only fingerprint | Content-aware index fingerprint | Known |
| FL-005 | 2026-08-16 | Verification | `BASE-001-CAND30`; positive candidates C02, C04, C06, C10, C12, C13, C14, C16, C17, C19, C20, C24, C26, C29, C30 | 15/30 known vulnerable clones entered `manual_review`; none were cleared | 50% positive-set abstention | Current +0.1 margin applied to verification score; these scores were below the flag boundary | Region-level/calibrated verification | Observed |

The failure ledger must distinguish:

- Known: supported by source inspection or an existing reproducible fixture;
- Observed: reproduced by a recorded run;
- Fixed: a change exists and has regression evidence;
- Resolved: fixed and re-measured on the relevant held-out cases.

## 8. Decision log

Every methodology change should have a corresponding decision entry. Record the
evidence that motivated the change and the measured result afterward.

| Decision ID | Date | Evidence IDs / runs | Change | Expected effect | Result | Decision |
|---|---|---|---|---|---|---|
| D-000 | 2026-08-16 | F-002, F-003, F-005, F-006, F-012 | Establish this evidence ledger before further changes | Prevent unmeasured changes and preserve comparability | Pending baseline runs | Active |
| D-001 | 2026-08-16 | F-002, F-003, F-007, F-012 | Planned pivot to multi-resolution AST-region retrieval with localized verification | Improve partial/large/structurally changed clone recall while preserving patched-code clearing | Not yet measured | Planned |

A decision may not be marked successful based only on an intuitive improvement. It
must reference a comparable before/after run using the same split and reporting
metrics.

## 9. Update protocol

When the methodology, corpus, model, threshold, or evaluation fixture changes:

1. Add a dated snapshot or result row; do not overwrite prior measurements.
2. Record the source commit and clean/modified working-tree state.
3. Record corpus size, advisory/repository split, model ID, and thresholds.
4. Separate retrieval misses from verification failures.
5. Report flagged, cleared, and manual_review separately.
6. Record unsupported syntax, skipped functions, and duplicate-CVE ambiguity.
7. Link the result to a failure or decision ID.
8. Preserve the raw output or a stable artifact path.
9. State whether the result is measured, source-derived, or an inference.
10. Re-run the same baseline whenever a new methodology is compared against the old one.

The primary comparison metrics are:

- vulnerable-region Recall@1, Recall@5, and Recall@10;
- candidate-level and region-level false-negative rate;
- alert precision at the intended review budget;
- patched-code clearing accuracy;
- manual-review/abstention rate;
- performance by transformation type;
- large-function and unsupported-syntax coverage;
- latency and alignment calls per candidate.

## 10. Current conclusion

The current evidence supports a pivot hypothesis, not a final accuracy claim:

- the corpus is small and concentrated in two packages;
- whole-function retrieval is vulnerable to dilution and truncation;
- verification thresholds and fallback score paths are not calibrated;
- the available clone benchmark is hand-authored and not statistically representative;
- on the 30-case positive fixture, retrieval reached every correct entry within the
  default shortlist, but verification flagged only half and abstained on half;
- fast tests validate mechanics, but broader advisory-disjoint real-model and
  end-to-end results remain to be recorded.

Until the baseline register contains advisory-disjoint results, claims about the
current detector should use terms such as “pilot,” “known limitation,” and
“unmeasured,” rather than reporting an overall accuracy percentage.
