# Expanded whole-function correspondence: findings

## Result

The expanded binding-aware AST check resolves **11 more snippets** than the prior
bounded guard/order/regex experiment: eight become correct-origin vulnerability
alerts and three become patched lineage. Including the previous three resolutions,
14 of the original 104 Tier 2 reviews are resolved. Ninety remain under review.

| Tier 2 evaluation: 422 cases | Original block/function | Prior bounded check | Expanded AST |
|---|---:|---:|---:|
| Correct-origin vulnerability alerts | 185/210 | 186/210 | **193/210** |
| Patched false alerts | 12/212 | 12/212 | **12/212** |
| Manual reviews | 73 | 71 | **62** |
| Patched cases released from original review | 0 | 1 | **3** |
| Vulnerable cases newly alerted from original review | 0 | 1 | **8** |
| Vulnerable cases released without an alert | 0 | 0 | **0** |

Across all 600 Tier 2 cases, correct-origin alerts increase from 266/301 to
276/301, false alerts remain 17/299, and reviews fall from 104 to 90. Four patched
cases are released and ten vulnerable cases gain alerts. Tier 1 and hash routes
remain unchanged. Adding the narrowly supported dead `void 0` branch removal
produces no additional gain, so the plain expanded AST arm is sufficient here.

## How the check resolves uncertainty

The complete candidate function must correspond to one distinct captured
reference side. The AST comparison tracks declarations and variable uses through
loops, async functions, destructuring, nested callbacks and shadowed scopes.
It recognises documented changes in presentation while retaining operations,
conditions, literals, external names, property keys and execution order. A direct
whole-function structural/token observation must also pass the existing gates.

The check retains every original boundary and established verdict. A mismatch
cannot reject an alternative boundary. A verified patch still does not release
the snippet when a credible unresolved alternative remains. L034 and LN018 both
retain manual review. Unknown helper calls are not assumed to return booleans;
therefore `helper(...) === false` is not treated as equivalent to `!helper(...)`.

## Additional resolved snippets

| Case | Split | Result | Evidence |
|---|---|---|---|
| L001 | Evaluation | Vulnerability alert | Parse Server `handleMe`: renamed bindings/shorthand expansion and a terminal throw with its continuation preserve the vulnerable function. |
| L079 | Evaluation | Vulnerability alert | Nuxt `redirect`: formatting and optional semicolons preserve the vulnerable references at two captured boundaries. |
| L084 | Evaluation | Vulnerability alert | Parse Server `requestResetPassword`: renamed bindings, preserved property keys, and unmodified lexical declarations correspond to the vulnerable reference. |
| L160 | Tuning | Vulnerability alert | Parse Server `metadataHandler`: async/catch structure and unmodified lexical declarations correspond to the vulnerable reference. |
| L256 | Evaluation | Vulnerability alert | Vite `getRelativeUrlFromDocument`: positive correspondence to vulnerable references across three existing boundaries. |
| L264 | Evaluation | Vulnerability alert | Vite `getRelativeUrlFromDocument`: positive correspondence to its vulnerable reference. |
| L267 | Evaluation | Vulnerability alert | Vite `getRelativeUrlFromDocument`: positive correspondence to vulnerable references across two existing boundaries. |
| LN154 | Tuning | Patched lineage | Nuxt `getContents`: renamed cache/matcher bindings preserve the patched references at two boundaries. |
| LN208 | Evaluation | Patched lineage | Better Auth `generateGenericState`: renamed bindings, expanded shorthand properties and added return type preserve the patched reference. |
| LN253 | Evaluation | Patched lineage | LiquidJS `candidates`: generator/loop structure, explicit branch braces and type annotations preserve the patched reference. |
| T2-4352b686dd1be168350f | Evaluation | Vulnerability alert | Undici `processHeader`: renamed bindings and a terminal throw followed by its continuation preserve the vulnerable reference. |

The renderer candidate A2-5ad6a4e4607479db85fa also gains a patched AST boundary
decision, but another unresolved boundary still requires review. This illustrates
why boundary resolutions and final snippet releases are different counts.

## Remaining reviews

Of the 90 remaining Tier 2 reviews, 67 are patched-labelled and 23 vulnerable-labelled:

- **43** already have at least one verified patched boundary, but competing
  uncertainty prevents release. This group includes both expected labels.
- **47** have neither a verified patched nor a verified vulnerable boundary.

There are 157 credible, non-rejected uncertain boundaries passing S/T among these
snippets: 70 have weak edit-side evidence, 70 weak side and margin evidence, and
17 ambiguous margins. These are boundary counts, not independent snippet counts.
`remaining-reviews.json` lists the cases and supporting measurements for further
work. It omits weak S/T-failed noise from its blocker lists; revision connections
can still require review separately.

Further reductions require additional correspondence rules or captured context
that establishes helper behaviour and boundary relevance. Lowering thresholds or
discarding unmatched alternatives would give larger apparent reductions without
establishing the intended conclusion.

## Validation and practical limits

**221 relevant tests pass**, including independent controls for changed guards,
inputs, calls, literals, operation order, shadowing, destructuring keys, special
`__proto__` properties, reflection and dynamic scope. An independent audit
reconstructs all 72 reported scopes, verifies all 1,200 source checkpoint seals
and identities, reproduces the previous bounded baseline, and checks retained
targets, established verdicts, hash results and L034/LN018 review.

No new false alerts or vulnerable releases without alerts occur on this cohort.
That observation is limited to these retrospective examples. The normalizer was
developed with inspected cases; the existing evaluation split is not an untouched
holdout. Whole-function correspondence is copied-structure evidence, not general
semantic equivalence, proof of provenance, exploitability or global safety.

No GPU/model inference, hosted AI calls, new retrieval or candidate execution was
used. Stored detector timing is the original baseline timing; recheck CPU time
is recorded separately. This remains an evaluation experiment. Production code
and original result files remain unchanged; integration and independent validation
are needed before enabling it in the main pipeline.
