# Readability-First Codebase Refactor Plan

## Status

Phase 0 has been captured in `REFACTOR_BASELINE.md`. Phase 1 was approved and is
implemented: 350 tests pass and all 600 fresh Tier 2 records match the pre-refactor
run exactly. Tier 1 reproduction remains blocked by unavailable GitHub access, so
its validation gate is still outstanding. Later phases remain proposals for
separate user review.

An approved follow-up groups `VulnerableRegionPair`, `VulnerabilityState`,
`RegionVerificationEvidence` and `HashMatch`, shares advisory/source contracts,
and adds one-line property explanations. This deliberately changes their internal
Python structure while preserving saved report, cache and retrieval JSON through
explicit record conversion. Its validation is recorded separately below the
original Phase 1 baseline: 363 tests pass, real CLI/cache findings match, and all
600 Tier 2 records match after correcting and replaying the evaluator's hash
identity scoring. Tier 1 reproduction still requires GitHub access.

The later model audit's phases 2 and 3 are also approved and implemented (these
are separate from the numbered migration phases below). Shared metadata now lives
in `shared/metadata.py`; corpus, retrieval and verification models compose advisory
and origin groups while retaining flat saved records. Boundary rejection,
contrastive selection and aggregate support counts are derived properties.
Validation: 370 tests pass, all 301 corpus records retain identical serialized
values, and fresh/cached CLI findings match. The full Tier 2 cohort was not rerun
for this extension. Comments are reserved for non-obvious fields.

Reviewed against the repository on 2026-09-19. The package tree below describes
the target architecture; it is not a complete file-move manifest.

Migration Phase 2 (CLI command extraction) was then authorized. Parser setup and
dispatch remain in `cli/main.py` (552 to 178 lines); execution now lives in
`cli/commands/{scan,report,corpus}.py`. All 379 tests pass, nine help outputs match,
and fresh/cached CLI findings match. The fresh full Tier 2 rerun matches all 600
candidate records and the summary exactly, excluding the generation timestamp.
Tier 1 remains blocked by a GitHub proxy error.

Migration Phase 3 (verification decomposition) was subsequently authorized.
`pipeline/detection/verification/` now owns sequence, structural, token, edit,
fallback, aggregation and classification logic. The verifier coordinates typed
reference-side evidence; the previous controller modules are import facades.
`EditDistanceEvidence` lives in `pipeline/models/evidence.py`. All 384 tests pass,
including performance checks; 384 region-evidence and 768 boundary-state comparisons
against the pre-extraction implementation match. Fresh/cached CLI findings match.
The fresh Tier 2 rerun matches all 600 records and the summary exactly, excluding
the timestamp. Tier 1 is still blocked by the proxy.
Migration Phase 4 (detector decomposition) is now authorized and implemented.
`pipeline/detection/{hashing,retrieval,lineage,priority}.py` owns result construction,
retrieval aggregation, lineage attribution and priority selection. `detect()` orders
these operations, with named methods for region verification and boundary decisions.
The optional local correspondence fallback remains explicit and late in that flow.
All 394 tests pass, fresh/cached CLI findings match, and all 600 Tier 2 records
match exactly except the timestamp. The user requested skipping the remaining
Tier 1 evaluation after 49 identical detector comparisons. Its full gate remains
unverified, as recorded in `REFACTOR_BASELINE.md`.
The shared GitHub client now loads the project `.env`, as separately requested.
Authenticated GitHub access succeeds outside the sandbox network restriction.
Phase 5 scanning decomposition has not started.

User review preference: present recommendations phase by phase for vetting before
implementing each phase. Prioritize readability, maintainability, clean code and
straightforward extension. The detailed migration recommendations remain proposals
until vetted.

## Objective

Make ProvTrail understandable from its runtime flow without requiring a reader to
reverse-engineer a large collection of controllers, models, scripts, and experiments.

The refactor should:

- make the production scan path obvious;
- place data models in clearly named, domain-focused modules;
- separate orchestration from algorithms and external integrations;
- separate production code from evaluation and research tooling;
- reduce the size and responsibility of the largest modules;
- preserve current behavior and evaluation results throughout the migration.

Readability takes priority over minimizing the number of files. However, the project
should avoid the opposite extreme of putting every individual class in its own file.
Each module should represent one cohesive concept.

## Current Problems

### Ambiguous `controller` packages

`pipeline/controller` currently contains several different kinds of code:

- workflow orchestration;
- detection algorithms;
- parsing and embedding adapters;
- persistence and incremental-scan behavior;
- configuration dataclasses;
- reporting;
- experimental fallback logic.

The name `controller` does not reveal which role a module performs.

### Models are only partially separated

Some models already live under `pipeline/models` and `corpus/models`, but important
models remain embedded inside implementation modules. In addition,
`pipeline/models/regions.py` contains region structure, retrieval, verification,
lineage, applicability, vulnerability state, and final-result models in one file.

### Large modules mix decisions with mechanics

The most important examples are:

- `cli/main.py`: parser construction and every command implementation;
- `pipeline/controller/region_detection.py`: the complete detection workflow and
  several result-building policies;
- `pipeline/controller/region_verification.py`: scoring, gates, aggregation,
  classification, and fallback decisions;
- `pipeline/controller/scanning.py`: discovery, caching, batching, scanning, project
  evidence, and result persistence.

### Product and research code look equally important

Tier evaluations, ablations, fixture generation, tool comparisons, smoke tests, and
maintenance commands are all presented as scripts. A new reader cannot immediately
tell which files implement ProvTrail and which files only measure it.

## Architectural Principles

### Organize production code by feature

The primary packages should correspond to the concepts in the product:

1. corpus construction;
2. vulnerability detection;
3. repository scanning;
4. reporting;
5. external integrations;
6. command-line entry points.

### Keep dependency direction clear

Dependencies should generally flow in one direction:

```text
models
  ↑
domain algorithms
  ↑
application services / orchestrators
  ↑
CLI
```

Models must not import scanners, CLI commands, databases, network clients, or report
writers. Domain algorithms should not parse command-line arguments or write files.

### Keep orchestration readable at a glance

High-level methods should describe the system in domain language. For example:

```python
def detect(candidate):
    validate(candidate)
    if hash_result := hash_matcher.match(candidate):
        return hash_result
    regions = extractor.extract(candidate)
    matches = retriever.retrieve(regions)
    evidence = verifier.verify(candidate, matches)
    return classifier.classify(candidate, evidence)
```

Details such as token scoring, AST containment, FAISS querying, and report formatting
should be delegated to focused modules.

### Prefer cohesive model modules

Do not create one file for every class. Group models that change together and describe
the same concept. For example, `AstRegion`, `SourceSpan`, and `CandidateRegion` belong
together, while the final scan result does not belong in the same module.

### Refactor incrementally

Every phase must leave the test suite passing. Old import paths should remain as
temporary compatibility facades until consumers have migrated.

## Proposed Production Structure

The final production package **must** use a `src` layout once imports and
packaging are ready for it. The target is:

```text
src/
└── provtrail/
    ├── cli/
    │   ├── main.py
    │   └── commands/
    │       ├── scan.py
    │       ├── report.py
    │       └── corpus.py
    ├── corpus/
    │   ├── models/
    │   │   ├── advisory.py
    │   │   ├── commit.py
    │   │   ├── diagnostic.py
    │   │   ├── entry.py
    │   │   └── build_result.py
    │   ├── builder.py
    │   ├── extraction.py
    │   ├── deduplication.py
    │   └── repository.py
    ├── detection/
    │   ├── models/
    │   │   ├── region.py
    │   │   ├── boundary.py
    │   │   ├── retrieval.py
    │   │   ├── evidence.py
    │   │   ├── lineage.py
    │   │   └── result.py
    │   ├── config.py
    │   ├── detector.py
    │   ├── hashing.py
    │   ├── extraction.py
    │   ├── retrieval.py
    │   └── verification/
    │       ├── verifier.py
    │       ├── structural.py
    │       ├── tokens.py
    │       ├── edit_distance.py
    │       ├── classification.py
    │       └── fallback.py
    ├── scanning/
    │   ├── models.py
    │   ├── scanner.py
    │   ├── discovery.py
    │   ├── cache.py
    │   └── project_context.py
    ├── reporting/
    │   ├── console.py
    │   ├── json_report.py
    │   └── html_report.py
    └── integrations/
        ├── github.py
        ├── osv.py
        ├── embeddings.py
        ├── vector_index.py
        ├── sqlite.py
        └── ollama.py
```

Adopting `src/provtrail` is a required outcome, but should be a late mechanical
phase. Earlier phases can improve the current package structure without
changing every import at once.

## Proposed Model Split

### Region models

`detection/models/region.py`:

- `RegionGranularity`
- `RegionChangeKind`
- `SourceSpan`
- `AstRegion`
- `CandidateRegion`

### Fix-boundary models

`detection/models/boundary.py`:

- `VulnerableRegionPair`
- `VulnerabilityStatus`
- `AbstentionReason`
- `EditStrategy`
- `SignatureEvidenceState`
- `FunctionIdentityState`
- `VulnerabilityState`

### Retrieval models

`detection/models/retrieval.py`:

- `RegionRetrievalMatch`
- `RegionAggregate`

`RegionRetrievalIndex` currently holds a `faiss.Index`. Keep it with the retrieval
adapter rather than moving it into the domain models.

### Verification evidence models

`detection/models/evidence.py`:

- `RegionVerificationEvidence`
- `ApplicabilityEvidence`
- `PackageApplicability`
- `ApplicabilityStatus`

### Lineage models

`detection/models/lineage.py`:

- `LineageConfidence`
- `LineageAttribution`
- detection-facing advisory aliases or references

### Result models

`detection/models/result.py`:

- `FindingPriority`
- `RegionDetectionResult`

### Models currently embedded in implementations

| Current model | Current location | Proposed location |
|---|---|---|
| `RegionDetectorConfig` | `region_detection.py` | `detection/config.py` |
| `RegionVerifierConfig` | `region_verification.py` | `detection/config.py` |
| `ScanConfig` | `scanning.py` | `scanning/models.py` |
| `ScanSummary` | `scanning.py` | `scanning/models.py` |
| `MerkleSnapshot` | `incremental.py` | `scanning/models.py` |
| `ScanState` | `incremental.py` | `scanning/models.py` |
| `EditDistanceEvidence` | `edit_distance.py` | `detection/models/evidence.py` |
| `CorpusFixBoundary` | `provenance.py` | `corpus/models/lineage.py` |
| `CorpusLineage` | `provenance.py` | `corpus/models/lineage.py` |

Private, implementation-only structures such as parsed-source caches may remain beside
the implementation when they are not part of a shared contract.

## Proposed Runtime Flow After Refactoring

A reader should be able to follow a scan through these files:

```text
cli/commands/scan.py
        ↓
scanning/scanner.py
        ↓
detection/detector.py
        ├── hashing.py
        ├── extraction.py
        ├── retrieval.py
        └── verification/verifier.py
                    ├── structural.py
                    ├── tokens.py
                    ├── edit_distance.py
                    └── classification.py
        ↓
reporting/json_report.py and reporting/html_report.py
```

The high-level detector should coordinate components but contain very little scoring
logic itself.

## Separate Production and Evaluation Code

Evaluation code should be visibly outside the production package:

```text
evaluation/
├── common/
│   ├── metrics.py
│   └── fixtures.py
├── tier1/
│   ├── build_targets.py
│   └── run.py
├── tier2/
│   ├── generate.py
│   └── run.py
├── ablations/
│   ├── retrieval.py
│   └── decision.py
└── comparisons/
    ├── build.py
    ├── run.py
    ├── score.py
    └── adapters/
        ├── semgrep.py
        └── codeql.py
```

Operational maintenance commands such as rebuilding the corpus should go under
`tools/`. Manual experiments and obsolete smoke scripts should be removed once their
coverage exists in automated tests.

## Phased Migration

### Execution and review boundaries

Treat each phase as a separate reviewable change; split large phases further when
needed. Extract existing behavior before changing dependency injection or public
interfaces. Each change records moved symbols, compatibility paths, validation
results, and any remaining blockers. A failed behavioral comparison blocks the
next phase until explained and resolved.

Before moving a module, inventory its import consumers, test patch targets,
serialized contracts, resource paths, and evaluation entry points. Existing tests
patch implementation locations (including CLI dependencies), so re-exporting a
symbol alone may not preserve a test seam. Update those seams deliberately while
retaining the behavior the tests exercise.

Use `pipeline/<feature>/` for new feature packages during Phases 3–6 and retain
old controller modules as facades where needed. Phase 1 uses the explicit paths
below; Phase 8 consolidates these into `src/provtrail`. Do not create a second
implementation under the final package while the original remains active.

### Phase 0: Establish safety checks

Before moving code:

- record the current full test result;
- record Tier 1 and Tier 2 result summaries;
- record representative CLI scan output;
- identify serialized models whose field names and JSON shape must remain stable;
- ensure no generated evaluation output is rewritten accidentally.

Exit criterion: there is a known behavioral baseline for later phases.

Record the baseline in a separate refactor validation document containing:

- Git commit, dirty/untracked file inventory, Python/dependency versions, platform,
  device and numeric precision;
- the full test command and counts of passed, failed, skipped and errored tests;
  report pre-existing failures separately, without describing the suite as passing;
- explicit Tier 1 and Tier 2 cohort/result filenames, corpus and index fingerprints,
  model revision, detector configuration, and hashes of input/result artifacts;
- representative saved scan JSON, console output, HTML generation, CLI exit codes,
  and a second scan demonstrating incremental reuse, all in an isolated output
  directory;
- a contract inventory covering report JSON, scan-state/cache JSON, corpus records,
  retrieval metadata, configuration fingerprints, and model JSON schemas.

The repository has multiple Tier 1/Tier 2 result variants, including FP32 results.
Select a matched pair by inspecting their recorded configuration; do not infer the
authoritative baseline from the newest filename. Existing artifacts are historical
evidence until reproduced. Never regenerate cohorts or overwrite existing results
to obtain a refactor baseline. If weights, indexes, network access, or release
checkouts are unavailable, record the missing prerequisite and leave that gate
pending rather than claiming evaluation equivalence.

### Phase 1: Split detection models

- Split `pipeline/models/regions.py` into cohesive model modules.
- Keep `pipeline.models.regions` as a temporary compatibility facade that re-exports
  the same public names.
- Move shared configuration dataclasses out of detector and verifier implementations.
- Do not change fields, defaults, validation behavior, or serialized JSON.

Use these interim canonical modules, with corresponding final modules as listed
in the target structure:

| Interim module | Responsibility |
|---|---|
| `pipeline/models/region.py` | Source spans, AST regions, candidate regions and region literals |
| `pipeline/models/boundary.py` | Vulnerable/patched pairs, vulnerability state and boundary literals |
| `pipeline/models/region_retrieval.py` | Region matches and aggregates |
| `pipeline/models/evidence.py` | Verification and applicability evidence |
| `pipeline/models/lineage.py` | Lineage attribution and confidence |
| `pipeline/models/result.py` | Final detection result and finding priority |
| `pipeline/detection/config.py` | Detector/verifier configuration and their shared defaults |

`pipeline/models/retrieval.py` already defines whole-function `RetrievalMatch`;
leave that contract in place during this slice. Existing advisory aliases remain
in `pipeline/models/provenance.py` and are imported by the new model modules.
Move shared default constants into a dependency-free configuration location and
re-export them from existing owners as needed. Configuration must not import
embedding, retrieval, or verifier implementations to obtain defaults.

Map dependencies before extraction: region and provenance contracts feed boundary
and retrieval contracts; evidence and lineage feed the final result. New modules
must import canonical peers directly, never the `regions.py` facade. Preserve
existing class identities through re-exports, including the old detector/verifier
configuration imports. Keep `EditDistanceEvidence`, scanning models and corpus
lineage extraction for their owning later phases.

Exit criteria:

- all existing imports continue working;
- model-specific tests pass;
- saved scan reports retain the same schema;
- no detection behavior changes.

### Phase 2: Split CLI commands

- Leave parser construction and dispatch in `cli/main.py`.
- Move scan execution to `cli/commands/scan.py`.
- Move report inspection to `cli/commands/report.py`.
- Move corpus build, probe, stats, import, and index actions to
  `cli/commands/corpus.py`.
- Keep command syntax and exit codes unchanged.

Exit criteria:

- `cli/main.py` is primarily parser setup and dispatch;
- CLI tests cover every command;
- help text, output paths, and exit codes remain stable.

### Phase 3: Decompose verification

- Move structural scoring into `verification/structural.py`.
- Move token, containment, and API-anchor scoring into `verification/tokens.py`.
- Keep edit-distance scoring in a dedicated module.
- Move boundary state and abstention decisions into
  `verification/classification.py`.
- Keep `verifier.py` as the coordinator that produces evidence.

Exit criteria:

- the main verifier reads as a sequence of named operations;
- all thresholds are defined in one configuration location;
- existing verification and performance tests pass;
- Tier 1 and Tier 2 outcomes are unchanged.

### Phase 4: Reduce the detector to orchestration

- Extract hash-result construction into the hash-matching component.
- Extract retrieval aggregation into the retrieval component.
- Extract lineage attribution into a lineage service.
- Keep `Detector.detect()` responsible for ordering these operations.
- Keep optional fallback invocation explicit and late in the flow.

Exit criteria:

- detector orchestration is understandable without reading scoring internals;
- fast-path and embedding-path behavior remain identical;
- fallback remains opt-in;
- all detector tests and evaluation baselines pass.

### Phase 5: Split repository scanning

- Move file discovery and function extraction to `scanning/discovery.py`.
- Move Merkle snapshot and result-cache logic to `scanning/cache.py`.
- Move project/manifest evidence to `scanning/project_context.py`.
- Keep batching and high-level execution in `scanning/scanner.py`.

Exit criteria:

- scanner control flow is visible in one module;
- incremental reuse behavior remains unchanged;
- cache compatibility is explicitly tested;
- reporting is not performed by the scanner itself.

### Phase 6: Separate integrations

- Put GitHub, OSV, Ollama, embedding-model, vector-index, and SQLite behavior behind
  clearly named adapters or repositories.
- Keep provider-specific retries, authentication, and response parsing within the
  relevant integration.
- Pass integrations into services rather than constructing them throughout domain
  logic where practical.

Exit criteria:

- network and persistence dependencies are easy to substitute in tests;
- domain algorithms do not make direct HTTP or database calls;
- existing retry and rate-limit behavior remains covered.

### Phase 7: Reorganize evaluation tooling

- Move Tier 1, Tier 2, ablation, and comparison programs into dedicated evaluation
  packages.
- Keep dataset generation beside the evaluation that consumes it.
- Give each evaluation one documented build/run/score entry point.
- Remove obsolete manual smoke scripts only after equivalent automated coverage is
  confirmed.

Exit criteria:

- production code can be understood without opening `evaluation/`;
- every retained result artifact has a documented reproduction command;
- comparison-tool setup remains separate from comparison execution.

### Phase 8: Introduce the final package layout

- Move all production Python packages under `src/provtrail`; do not leave
  parallel production implementations at the repository root.
- Configure package installation and a `provtrail` console entry point.
- Add `pyproject.toml` with declared dependencies and package data, including the
  HTML report template. Audit every `Path(__file__)` lookup before moving files:
  corpus databases, embedding indexes, snapshots and user caches are writable
  runtime data and must not depend on the installed package directory being writable.
- Update imports mechanically after the conceptual boundaries are stable.
- Remove compatibility facades only after repository-wide import migration.

Exit criteria:

- the project works from an installed package rather than relying on `PYTHONPATH=.`;
- production source resides under `src/provtrail`;
- tests import the installed package layout;
- there are no duplicate old and new implementations.
- a built wheel installs into a clean environment and runs CLI help, a fixture
  scan and HTML reporting from outside the repository without `PYTHONPATH`;
- corpus/index/cache locations resolve correctly with explicit paths and documented
  defaults, and packaged resources load from the installed distribution.

## Compatibility Strategy

During migration, old modules should re-export moved symbols:

```python
# Temporary compatibility facade
from pipeline.models.region import AstRegion, CandidateRegion, SourceSpan

__all__ = ["AstRegion", "CandidateRegion", "SourceSpan"]
```

Rules for compatibility facades:

- they contain imports only, never a second implementation;
- they are marked with a removal phase;
- new code imports the new canonical path;
- tests verify that old and new imports refer to the same class object;
- facades are removed together rather than disappearing unpredictably.

## Readability Rules for New Code

- Prefer explicit, straightforward code over clever abstractions. Introduce a
  shared abstraction for demonstrated common behavior, not hypothetical future use.
- Make extension points clear at real boundaries (retrieval providers, reporting
  formats, external services); avoid generic plugin frameworks or base-class
  hierarchies unless an existing requirement needs them.
- Use names and cohesive functions to explain the code. Keep comments sparse:
  document non-obvious reasoning, constraints and invariants, and remove stale
  narrative comments when touching the relevant code.
- A module should have one sentence that clearly explains its responsibility.
- Public functions should use domain language rather than stage numbers.
- Avoid generic names such as `utils.py`, `helpers.py`, and `controller.py`.
- Keep configuration in explicit typed objects rather than long parameter lists.
- Keep I/O at the edges of the system.
- Do not mix result formatting with detection decisions.
- Prefer functions small enough that their complete control flow fits on one screen,
  but do not split straightforward logic solely to satisfy a line-count target.
- Add comments for reasoning and invariants, not for restating code.
- Export a deliberately small public interface from each package.

## Testing Strategy

Each phase should run the relevant focused tests first, followed by the full suite.

Required regression layers:

1. model serialization and compatibility imports;
2. unit tests for extracted algorithms;
3. detector integration tests;
4. CLI and incremental-cache tests;
5. Tier 1 and Tier 2 evaluation comparison;
6. representative report snapshot or schema checks.

A structural refactor should not intentionally change thresholds, labels, retrieval
parameters, fallback defaults, or evaluation cohorts. Any behavioral improvement must
be proposed and measured separately.

Compare evaluations per candidate: retrieved identities/ranks, classifications,
abstentions and evidence must remain stable, in addition to aggregate metrics.
Compare on the same device, precision, corpus and indexes. Document any unavoidable
numeric tolerance before accepting results; do not introduce a tolerance merely
to conceal a changed decision. Normalize only known volatile output fields such
as elapsed time and temporary absolute paths.

For Phase 1, capture schemas and representative serialized payloads before moving
classes, then compare after extraction. Include vulnerable, patched, uncertain,
lineage-only and empty-result cases with nested evidence/defaults. Verify old and
new imports resolve to the same objects and old payloads still deserialize. A
round-trip through only the new classes is insufficient evidence of compatibility.

Full Tier 1/Tier 2 reruns are phase completion gates; use focused tests while
developing a phase. Run the existing verifier performance regression tests when
extracting scoring logic. Do not add arbitrary timing targets to mechanical moves.

## Remaining Mapping Decisions

Before their owning phases begin, complete the source-to-target inventory for
corpus admission/snapshot/release/sandbox logic, parser and hashing contracts,
whole-function retrieval, local correspondence, review explanations and their
cache, and the dashboard backend. These components exist today but are not all
represented in the illustrative target tree. Classify each as retained production,
evaluation-only, or removable with evidence; omission from the tree is not a
deletion instruction.

Keep generated datasets and historical results under their existing `eval/` paths
unless a separately inventoried move is necessary. `evaluation/` is the proposed
home for executable evaluation code. During Phase 7, preserve script entry points
with thin wrappers until documented commands and consumers have migrated.

## Documentation Deliverables

The completed refactor should include:

- a short architecture overview in the root README;
- one production runtime-flow diagram;
- one corpus-build flow diagram;
- a package-level README for evaluation tooling;
- documented public entry points for scan, corpus build/index, Tier 1, Tier 2, and tool
  comparison;
- removal of stale commands that refer to scripts no longer present.

## Definition of Done

The readability refactor is complete when:

- a new reader can identify the production code without inspecting evaluation scripts;
- the complete scan path can be followed through five or fewer orchestration files;
- shared data contracts live in explicit model modules;
- implementation modules no longer define unrelated public data models;
- CLI parsing is separate from command execution;
- detection orchestration is separate from scoring details;
- scanner orchestration is separate from cache and discovery mechanics;
- the test suite passes;
- Tier 1 and Tier 2 baseline results have not changed unintentionally;
- report JSON remains backward compatible or has an explicitly versioned migration;
- obsolete compatibility facades and smoke scripts are removed at the planned phase.

## Recommended First Implementation Slice

When implementation begins, Phase 1 should be the first pull request:

1. split `pipeline/models/regions.py` by concept;
2. preserve `pipeline.models.regions` as a compatibility facade;
3. move detector and verifier configuration objects into a dedicated configuration
   module;
4. add model import and serialization compatibility tests;
5. make no detector, threshold, or evaluation changes.

This provides an immediate readability improvement with a small behavioral risk and
creates clean boundaries for the later detector and verifier refactors.
