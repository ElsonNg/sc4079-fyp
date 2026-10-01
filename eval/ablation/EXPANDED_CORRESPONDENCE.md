# Expanded whole-function correspondence

## Purpose

Resolve more uncertain boundaries using positive correspondence to complete
captured reference functions. This experiment retains the vulnerable/patched
asymmetry: a patched boundary cannot dismiss another credible unresolved boundary.
It adds evidence rather than lowering fuzzy-match thresholds or deleting targets.

## Fixed experiment

Use the saved block/function study: 600 Tier 1 and 600 Tier 2 cases, the same
corpus, candidate boundaries, K5/B10, region limits and S/T/edit thresholds.
Use repeat 1 once for quality; do not count timing repetitions as new cases.
Reproduce the prior bounded guard/order/regex experiment as the first arm.

The expanded arms then inspect only eligible uncertain boundaries in reviewed
snippets. A direct complete-function observation must pass both S and T. Retain
hash results, established vulnerable/patched states, identity rejections and
explicit conflicts. Do not override disagreement between bounded recognizers.
The candidate must correspond to exactly one distinguishable reference side.
Mismatch or unsupported syntax leaves the boundary uncertain.

## What the new AST comparison preserves

The parser constructs a lexical binding graph before comparing complete syntax
trees. Each variable use remains linked to its declaration, including parameters,
destructuring, loops, nested callbacks, catch bindings and shadowed scopes.
Free identifiers, property keys, operators, calls, arguments, literals, async and
generator markers, branching and operation order remain visible.

Supported normalizations are explicit:

- Remove comments and optional semicolons; remove grouping only when it does not
  affect optional chaining or a string directive.
- Rename bound parameters/locals and the function label, preserving binding
  relationships and exposed property keys. Expand shorthand properties to their
  key/value form; preserve special `__proto__` prototype-setter syntax.
- Erase TypeScript type annotations, type arguments/parameters and access labels.
  These are runtime-independent for the supported function syntax.
- Treat plain single/double quoted strings with identical contents alike;
  escaped strings retain their original spelling.
- Treat unmodified lexical `const`/`let` bindings alike. Preserve differences for
  bindings assigned or updated anywhere, including nested callbacks.
- Fold an immediately returned lexical temporary into its expression, excluding
  expressions that create functions whose inferred names could change.
- Compare braced/unbraced conditional branches consistently. Fold `else` into the
  continuation only after a branch that unconditionally returns or throws;
  exclude branch-local function declarations.

The separate `expanded_ast_noop` arm also removes exactly an `if (false)` branch
containing only `void 0`. Other unreachable bodies remain visible, including
declarations that could change hoisting. The main `expanded_ast` arm does not
remove this branch. The two expanded arms have identical cohort outcomes.

Abstain on malformed/surrounding code, unsupported classes or dynamic scope,
duplicate or unsupported bindings, block-local function declarations, detected
reflection on locally created functions, ambiguous method self-reference, and
size/depth limits. This is copied-structure evidence, not a general theorem of
semantic equivalence. Local names or function source can be observed by external
code; the snippet/corpus cannot establish all surrounding runtime behaviour.

## Run and audit

```powershell
.venv\Scripts\python.exe -m eval.ablation.run_expanded_correspondence
.venv\Scripts\python.exe -m eval.ablation.audit_expanded_correspondence
```

The runner refuses a nonempty output directory; use `--output` with a fresh path
for repeats. Pass the same path to the auditor. Source study/input hashes,
checkpoint seals, candidate identities and baseline metrics are verified. The
auditor independently reconstructs every metric scope, checks the prior bounded
baseline, and preserves L034/LN018 review. Source code and report hashes are saved.

Outputs default to `eval/frozen/active-expanded-correspondence-v1`. Stored detector
timings are the original baseline timings. Additional recheck CPU seconds are
separate and do not measure end-to-end detector time. No retrieval, GPU/model
inference, hosted AI calls or candidate execution is performed.

## Interpretation

The existing grouped tuning/evaluation split remains retrospective. Some examples
informed the supported normalizations. Handwritten adversarial controls validate
the rules, but these results do not establish performance on an untouched holdout.
No production defaults or original studies are changed. Promote only after a
separate integration run and validation against additional independent examples.
The remaining-review inventory describes blockers for further work; it does not
use expected labels to choose a verdict.
