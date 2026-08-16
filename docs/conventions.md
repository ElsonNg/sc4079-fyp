# Project Conventions

This document is the working engineering guide for provtrail. It describes the
current pipeline and the conventions required by the planned AST-region retrieval
pivot. The pivot's architecture and rationale are documented in
[PIVOT.md](PIVOT.md).

The goal is to keep pipeline stages independently testable, manually inspectable,
and safe to compare during the migration.

## 1. Pipeline terminology

Use these logical stage names in documentation, test names, smoke scripts, and
validation output:

1. **Corpus acquisition and extraction** — obtain advisory, commit, file, and
   vulnerable/patched function data.
2. **Parsing and function discovery** — parse JavaScript and identify function units,
   methods, source ranges, and unsupported syntax.
3. **Hashing** — perform exact and identifier-abstracted whole-function matching.
4. **AST-region generation** — derive changed corpus regions and meaningful candidate
   regions at multiple granularities.
5. **Semantic retrieval** — retrieve vulnerable corpus regions for candidate regions.
6. **Verification** — compare AST structure, normalized tokens, local semantics, and
   local alignment where required.
7. **Decision and evidence reporting** — contrast vulnerable and patched regions and
   emit a flagged, cleared, or manual-review result.

The current implementation combines stages 4–6 differently: whole-function
retrieval is followed by hierarchical/flat alignment and then vulnerable/patched
verification. New work should use the logical names above while preserving the
current implementation names in compatibility notes where necessary.

## 2. Repository layout

Keep responsibilities separated by directory:

~~~text
corpus/
  controller/       Advisory ingestion, commit extraction, persistence, corpus build
  models/           Corpus, advisory, commit, and extraction data contracts
  data/             Local/generated corpus database and embedding artifacts

pipeline/
  controller/       Parsing, hashing, embedding, retrieval, alignment, verification
  models/           Pydantic contracts for stage inputs and outputs

tests/              Automated unit and integration tests
scripts/            Manually runnable smoke, validation, rebuild, and diagnostic tools
examples/           Small fixtures intended for human inspection
docs/               Architecture, conventions, and investigation notes
dashboard/          Presentation/API layer; delegates behavior to pipeline controllers
cli/                CLI entrypoint layer; delegates behavior to pipeline controllers
~~~

Conventions:

- Put domain behavior in corpus/controller/ or pipeline/controller/; do not
  duplicate controller logic in scripts, dashboard handlers, or CLI commands.
- Put shared input/output contracts in the corresponding models/ directory.
- Keep generated databases, FAISS indexes, and model artifacts under corpus/data/.
  Do not hand-edit them.
- Put small, readable fixtures in examples/ when they are useful outside a single
  test module. Keep test-only fixtures in the relevant test file or test fixture
  helper.
- Put durable project decisions and investigation results in docs/; keep source
  comments focused on local behavior and invariants.
- A script may compose existing controllers, print diagnostics, and return an exit
  status. It must not become a second implementation of a pipeline stage.

## 3. Engineering patterns

### Stage boundaries

Each stage should have a typed boundary and a small public surface:

- controller functions accept explicit inputs and return typed models or documented
  primitive values;
- Pydantic models define data that crosses controller boundaries;
- pure transformations remain separate from network, filesystem, database, and model
  loading operations;
- optional dependencies such as model IDs, thresholds, caches, and HTTP sessions are
  passed explicitly when they affect behavior.

The caller owns reusable caches. In particular, an EmbeddingCache should be shared
across related comparisons for one candidate, but it must not hide corpus or model
state that the caller cannot inspect.

### Determinism and configuration

- Use fixed seeds for sampled validation sets.
- Keep evaluation selections and exclusions auditable in the script that defines
  them.
- Centralize thresholds and calibration constants. Every threshold must document its
  unit, calibration source, and intended use.
- Do not use a retrieval threshold as a final vulnerability verdict.
- Separate model-specific calibration from model-independent logic.
- Include model ID, preprocessing configuration, and source content in persisted
  embedding-index freshness checks.

### Source and coordinate handling

Maintain separate representations for:

1. raw source text, used for reporting and source spans;
2. normalized source text, used for comparison and embeddings;
3. AST nodes and byte ranges, used for structure;
4. raw zero-indexed line numbers, used for diagnostics and evidence.

Rules:

- Raw source lines are zero-indexed throughout the pipeline.
- Any synthetic parser wrapper must translate byte and line ranges back to the
  original snippet before returning them.
- Comment/whitespace normalization must never be used as a substitute for source
  coordinate mapping.
- Every evidence result must be traceable to a corpus identity, candidate identity,
  AST region, and source-line span.

### Error and uncertainty handling

Make these states explicit:

- parser failure or unsupported syntax;
- function skipped because its AST is unreliable;
- missing or stale retrieval index;
- empty diagnostic region;
- duplicate vulnerable code associated with multiple advisories;
- ambiguous vulnerable-versus-patched evidence;
- manual review required.

Do not silently turn unsupported syntax or missing evidence into “cleared.” A result
may be manual_review or an explicit unsupported outcome when the detector cannot
make a reliable decision.

### AST-region conventions

For the pivot, do not embed every raw AST node independently. Tiny nodes lose the
context needed to distinguish security behavior from boilerplate.

Use multiple region granularities:

1. changed statement or expression;
2. enclosing control-flow block;
3. context-expanded vulnerability slice;
4. complete function as a fallback.

Each region should preserve:

- source span and enclosing function identity;
- AST node type and parent/path context;
- normalized tokens, operators, literals, and member accesses;
- relevant calls and definitions/uses where available;
- vulnerable/patched pairing for corpus regions;
- region granularity and extraction reason.

Semantic similarity is evidence for candidate generation, not proof of provenance.
Structural and local semantic checks must follow retrieval before a result is
flagged.

## 4. Automated test conventions

### File and test naming

- Use tests/test_<controller>.py for tests focused on one controller.
- Use tests/test_<behavior>.py only when a behavior intentionally spans multiple
  controllers.
- Name tests as observable behavior, for example
  test_renamed_variant_retrieves_matching_entry.
- Keep fast deterministic tests enabled by default.
- Mark tests that load real model weights, FAISS indexes, or other expensive local
  resources with the existing slow marker.

### Required test layers for new stages

Every new stage must include:

- pure unit tests for normal cases, boundary cases, and failure paths;
- fixture-based integration tests using fakes where model behavior is not under test;
- one manually runnable smoke script using the real dependency when real behavior is
  the subject;
- one validation scenario if the stage changes end-to-end detection or evidence.

Tests should assert contracts and invariants rather than incidental embedding values.
Real-model tests may assert score ordering, match/gap behavior, retrieval rank, or
status buckets, but must document model-specific calibration assumptions.

### Minimum test matrix

Cover these transformations across relevant stages:

- exact vulnerable and patched functions;
- formatting and comment changes;
- identifier renaming;
- inserted and deleted guards;
- statement splitting and merging;
- reordered statements;
- extracted or inlined logic;
- API or expression rewrites;
- unrelated same-package functions;
- generic boilerplate hard negatives;
- duplicate vulnerable code linked to multiple CVEs;
- unsupported syntax and parser errors;
- large functions and empty diagnostic regions.

## 5. Manual smoke-test conventions

Smoke tests are short, human-readable checks for running one stage manually. They
are not substitutes for the full validation suite.

### Naming and structure

Use:

~~~text
scripts/smoke_test_<stage>.py
~~~

Each smoke script must have a module docstring containing:

- the stage under test;
- what dependencies it loads;
- whether it uses real model weights or network access;
- the exact repository-root command;
- known calibration or interpretation caveats.

Each script should:

- use small deterministic fixtures;
- print stage name, case name, model ID, important scores, and expected outcome;
- include at least one positive, one negative, one transformation, and one ambiguous
  or failure case;
- exit 0 only when all declared invariants pass;
- exit nonzero when a regression invariant fails;
- avoid modifying corpus databases, indexes, or tracked files.

### Canonical smoke scripts

The project should maintain one canonical script per logical stage:

~~~text
scripts/smoke_test_corpus.py
scripts/smoke_test_parsing.py
scripts/smoke_test_hashing.py
scripts/smoke_test_region_retrieval.py
scripts/smoke_test_ast_verification.py
scripts/smoke_test_alignment.py
scripts/smoke_test_verification.py
~~~

During migration, existing smoke_test_alignment.py and smoke_test_hierarchy.py
remain valid for the current implementation. New region retrieval and AST
verification scripts should be added without deleting those regression checks until
the pivot replaces the old path.

### Stage-specific smoke expectations

- **Corpus:** verify vulnerable/patched pairing, source spans, identity uniqueness,
  and diagnostic-region extraction.
- **Parsing:** verify declarations, expressions, arrows, methods, nested functions,
  anonymous functions, raw line mapping, and unsupported syntax reporting.
- **Hashing:** verify exact matches, normalized matches, renamed identifiers, short
  unhashable functions, and unrelated-function rejection.
- **Region retrieval:** verify a vulnerable region is retrieved inside a larger
  candidate, hard negatives are not top-ranked, duplicate advisory identities are
  preserved, and stale indexes are detected.
- **AST verification:** verify compatible structure, renamed structure, split/merged
  statements, reordered statements, incompatible node types, and patched-region
  contrast.
- **Alignment:** verify insertion, deletion, split/merge, unrelated regions, and
  source-line coordinate mapping.
- **Decision:** verify vulnerable clone → flagged, patched clone → cleared, and
  ambiguous/unsupported evidence → manual_review or explicit unsupported status.

## 6. Validation-script conventions

Validation scripts are repeatable, broader checks with explicit pass/fail criteria.
They must document the dataset, selection, expected status, and known limitations in
their module docstring.

Use:

~~~text
scripts/validate_<scope>.py
~~~

Canonical validation responsibilities:

- validate_corpus.py: corpus integrity, identity uniqueness, vulnerable/patched
  pairing, source-span validity, parser coverage, and index freshness;
- validate_e2e.py: fixed-sample self-anchor and self-clear checks;
- validate_worst_case.py: hand-authored Type-2/3 clone pilot, explicitly labeled
  as non-statistical;
- validate_pivot.py: advisory-disjoint comparison of current whole-function
  retrieval versus AST-region retrieval;
- evaluate_<experiment>.py: metric-producing experiments that are not release gates.

Validation output must include:

- dataset/split name and size;
- model and configuration;
- stage-level pass/fail counts;
- retrieval misses separated from verification failures;
- manual-review/abstention counts;
- parser and unsupported-syntax counts;
- concise failure records containing corpus identity and source region.

Default output is human-readable stdout. Add --json only when machine-readable
output is needed. Do not silently write reports or mutate persisted data.

### Evaluation split rules

At minimum, split by advisory. Prefer repository- and time-disjoint evaluation for
generalization claims. A vulnerable function or region must not appear in both the
retrieval index and the test set.

Report separately:

- hash match rate and false-positive rate;
- retrieval Recall@1, Recall@5, and Recall@10;
- misses caused by threshold filtering;
- verification precision, recall, and manual-review rate;
- end-to-end alert precision and false-negative rate;
- transformation-specific performance;
- large-function performance;
- latency and alignment calls per candidate.

## 7. Manual commands

Run commands from the repository root:

~~~text
PYTHONPATH=. .venv/bin/python scripts/smoke_test_<stage>.py
PYTHONPATH=. .venv/bin/python scripts/validate_<scope>.py
PYTHONPATH=. .venv/bin/python -m pytest -m "not slow"
PYTHONPATH=. .venv/bin/python -m pytest -m slow
PYTHONPATH=. .venv/bin/python -m pytest
~~~

Use the actual script name in place of <stage> or <scope>.

Network-dependent operations such as corpus rebuilding must be clearly separated
from local validation. They must state that they may replace persisted corpus data
and must not be required for the default local smoke-test path.

## 8. Change checklist

Before merging a new stage or changing an existing one, confirm:

- the stage has a typed controller boundary;
- pure logic is covered by fast tests;
- model/network behavior has an appropriate slow or smoke test;
- normal, negative, transformation, and uncertainty cases are represented;
- source coordinates map back to the original candidate and corpus text;
- thresholds and calibration assumptions are documented;
- manual scripts print interpretable evidence and return meaningful exit codes;
- validation separates retrieval misses from verification errors;
- no script duplicates controller behavior;
- generated corpus/index artifacts are not hand-edited;
- PIVOT.md and this document remain consistent.

The target operating principle is:

> AST-region retrieval provides recall, AST and local semantic checks provide
> confidence, and localized line alignment provides edit handling and explainable
> evidence.

