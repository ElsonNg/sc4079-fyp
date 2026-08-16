# Vulnerable Clone Detection Pivot Plan

## Decision

Pivot from whole-function embedding retrieval followed by whole-function
hierarchical line alignment to **multi-resolution AST-region retrieval followed by
localized structural verification**.

The current pipeline should not be discarded. It should be divided into roles:

- hashing remains a fast, high-confidence exact/abstracted-match path;
- semantic embeddings move to the candidate-region retrieval stage;
- AST matching becomes the main verification mechanism;
- line alignment becomes a localized fallback and evidence generator;
- vulnerable-versus-patched comparison remains the final contrastive check.

The target question changes from:

> Which historical vulnerable function does this whole function resemble?

to:

> Does any region of this candidate correspond to a known vulnerable region, and
> does it correspond more strongly to the vulnerable version than to the paired
> patched version?

## Current methodology

```text
candidate whole function
  -> exact/abstracted whole-function hashing
  -> whole-function embedding retrieval against vulnerable functions
  -> hierarchical/flat alignment against the vulnerable function
  -> hierarchical/flat alignment against the patched function
  -> score difference and verdict
```

The current strengths are exact known-source detection, identifier-renamed clone
detection, and a useful vulnerable/patched contrast. Its main limitations are that
retrieval is whole-function based, vulnerable changes can be diluted inside large
functions, the score margin is not calibrated, and global order-preserving line
alignment is fragile under larger refactorings.

## Target methodology

```text
corpus vulnerable/patched commit pairs
  -> identify changed vulnerable regions
  -> extract AST slices plus context and metadata
  -> embed/index slices at multiple granularities

candidate function
  -> parse and enumerate meaningful AST regions
  -> retrieve candidate regions against vulnerable-region index
  -> aggregate region hits by CVE/function/commit
  -> structurally verify candidate region against vulnerable region
  -> compare the same region against the paired patched region
  -> run local line alignment only when needed
  -> calibrated verdict with evidence or manual review
```

The pivot is only material if the indexed and queried units become smaller than
whole functions. Replacing one whole-function embedding model with another would
not address the main failure mode.

## What changes and what stays

| Component | Current role | Target role |
|---|---|---|
| Exact hash | Whole-function fast path | Keep for known-source matches; optionally add subtree hashes later |
| Abstracted hash | Identifier-normalized whole-function match | Keep as a high-confidence fast path, not the general detector |
| FAISS retrieval | Search whole vulnerable functions | Search vulnerable AST slices, changed hunks, and contextual slices |
| AST parser | Extract functions and guide alignment | Extract functions, changed regions, candidate regions, and structural evidence |
| Hierarchical alignment | Main post-retrieval similarity mechanism | Replace global use with localized fallback/evidence mapping |
| Patched function | Compared after vulnerable retrieval | Paired negative/reference used during verification and scoring |
| Diagnostic lines | Line-level diff metadata | Seed vulnerable-region extraction and evidence localization |
| Thresholds | Fixed `0.7` retrieval and `0.1` verification defaults | Calibrate on held-out data; abstain when confidence is insufficient |
| Corpus identity | CVE/GHSA and commit metadata | Retain, while adding slice identity and source-region metadata |

## Phase 0: establish the evaluation baseline

Before changing the detector, freeze a baseline report for the current pipeline.
The report must separate:

1. hash match rate and false-positive rate;
2. retrieval Recall@1, Recall@5, and Recall@10;
3. retrieval misses caused by the similarity threshold;
4. verification precision, recall, and manual-review rate;
5. end-to-end alert precision and false-negative rate;
6. latency and number of alignment calls per candidate.

The evaluation split must be by advisory at minimum. A stronger split is by
repository and time. A vulnerable function must not appear in both the index and
the test set, otherwise self-anchor results measure plumbing rather than
generalization.

The test set should contain:

- exact vulnerable and patched examples;
- identifier-renamed clones;
- formatting and comment changes;
- inserted/deleted guards;
- statement splitting and merging;
- reordered statements;
- extracted or inlined logic;
- API and expression rewrites;
- naturally occurring clones from other repositories;
- hard negatives from the same package and nearby functions;
- patched versions and unrelated functions with similar boilerplate.

## Phase 1: enrich the vulnerability corpus

For every corpus entry, retain the existing vulnerable function, patched function,
CVE/GHSA metadata, and commit identity. Add region-level records containing:

- vulnerable source span and patched source span;
- the changed AST subtree or smallest enclosing structural region;
- one or more context-expanded regions;
- AST node type and parent path;
- normalized tokens and literals/constants;
- calls and relevant definitions/uses where available;
- whether the change is an insertion, deletion, replacement, or movement;
- the fix type, such as guard addition, validation change, escaping change, or
  authorization change.

Use multiple region sizes rather than choosing one universal slice:

1. changed statement or expression;
2. enclosing control-flow block;
3. context-expanded vulnerability slice;
4. complete function as a fallback.

The patched slice must be paired with the vulnerable slice using the same corpus
identity. A CVE label alone is not enough; the system needs to know exactly which
candidate region is being compared with which vulnerable and patched regions.

## Phase 2: candidate AST-region generation

Parse each target function once and enumerate meaningful regions, prioritizing:

- conditions and their bodies;
- calls, member accesses, and sink/source-like expressions;
- loops, exception handlers, and authorization branches;
- changed-looking or high-information statements;
- enclosing blocks for each smaller region;
- the whole function as a fallback.

Do not embed every raw AST node independently. Tiny nodes lose context and create
many noisy retrieval hits. Each region should carry its node type, AST path,
surrounding statements, and relevant data-flow context into the embedding text.

The same candidate may therefore issue several retrieval queries. Hits must retain
the candidate region coordinates so that retrieval can be traced back to source
lines and AST nodes.

## Phase 3: region-level semantic retrieval

Build a retrieval index over vulnerable corpus regions. Keep separate metadata for:

- CVE/GHSA identity;
- vulnerable region;
- paired patched region;
- repository, commit, file, and function;
- region granularity and AST path.

For each candidate region, retrieve a generous shortlist for recall. Aggregate
multiple hits belonging to the same corpus entry using more than the single best
similarity. Useful evidence includes:

- best region similarity;
- number of supporting candidate regions;
- coverage of the vulnerable region;
- agreement between granularities;
- whether the hit is isolated to a specific CVE entry or duplicated across entries.

Do not treat the embedding threshold as a verdict. It is only a candidate-generation
filter and must be calibrated separately for region size and model.

The current whole-function index should remain as a fallback during migration so
that recall can be compared directly.

## Phase 4: localized AST verification

For every shortlisted candidate-region/corpus-region pair, verify in stages:

1. **Structural compatibility**: compare AST node types, child structure, control-
   flow role, and AST-path context.
2. **Normalized token evidence**: compare identifiers by role, operators, literals,
   member accesses, and calls.
3. **Local semantic evidence**: compare relevant definitions/uses, predicates,
   sink/source relationships, and security-sensitive API roles.
4. **Vulnerable-versus-patched contrast**: require stronger evidence for the
   vulnerable region than for the paired patched region, especially around the
   diagnostic change.
5. **Local line alignment**: use the existing alignment primitive only inside the
   matched regions when statements were split, merged, inserted, deleted, or need
   source-line evidence.

The current global whole-function alignment should no longer be the only mechanism
responsible for finding or accepting a clone. AST matching alone should also not be
treated as proof: identical AST shape can implement different behavior, while
semantically equivalent code can have different AST shape.

## Phase 5: scoring and verdicts

Replace the single uncalibrated score difference with an evidence record containing:

- retrieval similarity and rank;
- vulnerable-region structural score;
- patched-region structural score;
- AST and token coverage;
- data/control-flow agreement;
- local alignment quality where used;
- vulnerable-minus-patched margin;
- fallback paths used;
- duplicate or ambiguous provenance candidates.

Use three outcomes:

- **flagged**: strong vulnerable evidence and no comparable patched match;
- **cleared**: strong patched correspondence or weak vulnerable evidence;
- **manual review**: ambiguous, incomplete, unsupported, or conflicting evidence.

Calibrate thresholds on held-out advisories and report performance separately for
insertions, deletions, replacements, reordered code, and large functions. Do not
pool fallback and non-fallback verification scores until they are put on a common
validated scale.

## Phase 6: provenance interpretation

The system should distinguish two outputs:

1. **Vulnerability-clone evidence**: the candidate appears to preserve the same
   vulnerable behavior or vulnerable code pattern.
2. **Source-provenance evidence**: the candidate likely descends from the historical
   code, based on unusually specific structure, constants, call sequences, and
   region correspondence.

Semantic similarity and AST matching can support provenance, but they cannot prove
that independently authored code came from the CVE’s source. Provenance claims must
therefore be phrased as confidence levels unless repository history or other lineage
evidence is available.

## Migration order

### P0 — Measurement

- Freeze current baseline metrics.
- Add advisory/repository-disjoint evaluation splits.
- Add hard negatives and transformation-specific cases.
- Record retrieval misses separately from verification errors.

### P1 — Corpus slices

- Derive vulnerable and patched AST regions from existing diagnostic lines.
- Store region identity and paired vulnerable/patched metadata.
- Validate that each slice maps back to source lines and an enclosing function.

### P2 — Region retrieval

- Generate meaningful candidate AST regions.
- Add region embeddings and multi-resolution retrieval.
- Keep whole-function retrieval as a fallback.
- Aggregate region hits by CVE/function/commit.

### P3 — Local verifier

- Add AST structural and normalized-token checks.
- Add vulnerable-versus-patched region comparison.
- Retain local line alignment for split/merge and evidence mapping.
- Stop using whole-function alignment as the sole acceptance signal.

### P4 — Calibration and ablation

Compare the following under the same held-out split:

- current pipeline;
- region retrieval only;
- region retrieval plus AST verification;
- region retrieval plus AST verification plus local alignment;
- the full hybrid including hashes and whole-function fallback.

Select the pivot only if it improves vulnerable-region recall without an unacceptable
increase in false positives or manual-review volume.

### P5 — Operational hardening

- Include source content and model configuration in index fingerprints.
- Make parser failures explicit rather than silently treating missing regions as no
  vulnerability.
- Record unsupported syntax and skipped functions.
- Deduplicate identical vulnerable code while preserving all CVE associations.
- Add evidence-rich output showing candidate lines, matched AST regions, and the
  vulnerable/patched comparison.

## Success criteria

The pivot is successful when, on advisory-disjoint evaluation data, it demonstrates:

- higher Recall@K for renamed, partial, and structurally changed clones;
- no material degradation for exact and patched-code clearing;
- calibrated alert precision at the intended review budget;
- fewer retrieval misses on large functions;
- explicit and reproducible evidence for every flagged result;
- a useful abstention/manual-review category rather than forced binary decisions.

The intended end state is not “AST instead of line alignment.” It is:

> AST-region retrieval for recall, AST/data-flow verification for confidence, and
> local line alignment for edit handling and explainable evidence.
