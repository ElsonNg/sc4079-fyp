# Corpus validation status

The latest pass is [revalidation-v7-utf8](../frozen/revalidation-v7-utf8/report.md), following [revalidation-v6](../frozen/revalidation-v6/report.md). The complete candidate pools remain **600 Tier 1 targets and 788 Tier 2 transformations**. No original fixture was deleted, repaired in place, or relabelled.

| Evidence outcome | Tier 1 | Tier 2 |
|---|---:|---:|
| Executable security-boundary evidence | 198 | 263 |
| Bound source-and-patch review with preservation evidence | 52 | 16 |
| Behaviour mismatch under the recorded test context | 0 | 53 |
| Runtime syntax failure | 0 | 2 |
| Requires further evidence/review | 332 | 427 |
| Reference/source mismatch | 18 | 27 |
| Total | 600 | 788 |

Thus **250 Tier 1 and 279 Tier 2 cases have supporting validation evidence**. This is bounded extracted-function evidence, not a full-package security guarantee. All review is automated; no human validation is claimed. The earlier 582 Tier 1 figure counted matching source identities, not independently validated security labels.

For Tier 2, **230 cases (115 pairs, 16 packages)** additionally satisfy complete vulnerable/patched pairing and unique-source rules. The two latest batches retain the previous 202 pair-eligible cases and add 28 cases. All eight expansion packages contribute to this proposed subset, but it does not provide 22-package coverage. The other 49 individually supported cases remain ineligible under the pair/duplicate rules. Of the 230 pair-eligible cases, 225 have unconfirmed clone categories, three are mechanically Type 1 and two are mechanically Type 2; requested Type 3/4 must not be reported as confirmed classifications.

The two latest batches execute 70 cases across 17 reference origins. They add supporting evidence for 63 previously unresolved cases (30 Tier 1 and 33 Tier 2), upgrade four Tier 1 source reviews to executable evidence, and find three additional behaviour mismatches. Other results are inherited from verified previous reports. **804 cases remain unresolved across 196 advisory/fix/function origins**, and 55 cases have failed checks requiring repair/revalidation or exclusion.

| Batch | Cases executed | Origins | Newly supported | New failures |
|---|---:|---:|---:|---:|
| v6: routing and schema selection | 50 | 9 | 43 | 3 |
| v7: cookies and proxies | 20 | 8 | 20 | 0 |

Fourteen of the 18 Tier 1 reference mismatches have exact historical target sources recoverable from preserved Tier 2 originals, with matching advisory/fix/path/function identity and target hashes. They remain excluded pending security review and reconciliation with the current reference. The report records their provenance without replacing the current reference source.

The original `experiment-v2` freeze still uses its existing 60 Tier 2 admissions and remains byte-valid. Revalidation outputs propose a subsequent cohort; adopting it for ablations requires a new compatible freeze and grouped split. No full ablations were run. `revalidation-v2` through `revalidation-v6` are preserved previous passes. The first `revalidation-v7` output is superseded by `revalidation-v7-utf8` because its resume reader mishandled Unicode separators; all test observations and verdicts are identical in the corrected run. `revalidation-v1` was an intermediate development pass and is superseded.

## Evidence and follow-up

- [validation.jsonl](../frozen/revalidation-v7-utf8/validation.jsonl): a separate record for every one of the 1,388 candidates, including source identity, parsing/diagnostic screens, exact test observations, source audits, reviewer type and outcome.
- [changes.jsonl](../frozen/revalidation-v7-utf8/changes.jsonl): exact changes from the previous pass, including source-review upgrades separately from newly supported cases.
- [tier2-paired.jsonl](../frozen/revalidation-v7-utf8/tier2-paired.jsonl) and [tier1-validated.jsonl](../frozen/revalidation-v7-utf8/tier1-validated.jsonl): the proposed supported subsets.
- [followup.jsonl](../frozen/revalidation-v7-utf8/followup.jsonl): remaining work grouped by tier, origin and outcome. Missing helpers/context require exact matching source evidence; failed transformations need a new version with their original failure retained.
- [verification.json](../frozen/revalidation-v7-utf8/verification.json): 210 relevant tests passed, including 33 new tests across these two batches; resume preserved all output hashes and checkpoint modification time. Prior report files remained byte-identical; all denominators and retention of every previously supported case were checked.

The boundary suite covers JavaScript and TypeScript and distinguishes the original vulnerable/patched sources before admitting a transformed source. It exercises prototype guards, redirect headers and URLs, framing headers, quoted recipient tokens, JWT policy arguments, and existing length/exception/comment guards. Dependency stubs and limits are recorded per case. Passing a bounded test cannot override a previously recorded candidate defect outside the test's scope. Non-distinguishing tests and failing reference execution remain inconclusive.

The preceding v3 batch tests Electron option inheritance, LiquidJS allocation accounting, Fastify stream backpressure, Nuxt meta-refresh normalization with the exact matching encodeURL helper, Undici URL origin preservation and cookie paths, Unicode length accounting, Parse Server session fields and token conversion, and GraphQL traversal limits. Its oracles require the specific intended security witness (false on the vulnerable original, true on the patched original), rather than accepting arbitrary original output differences. Each candidate must also match all ordinary/error controls. Promise tests use real promises rather than requiring identical callback identities.

The v4 batch tests Axios prototype keys, Moment locale traversal, Undici header validation, Nuxt route-path casing, Multer cleanup, Parse Server user authorization arguments, WebSocket upgrade errors, Handlebars generated lookup code, Vite generated document-base selection, and Fastify MIME-parser selection. [Cached upstream context](../frozen/helper-context-v1/README.md) supplies exact-fix helpers and matching licenses; its URLs and hashes are recorded per test. Fastify uses content-type v1.0.4 as a compatible pinned test dependency, without claiming it was the historical resolved version.

Valid programs with one declared callable are executed through that binding; the multi-function L257 entry is selected by an explicit source-hash-bound automated review. Ambiguous entry points are inconclusive, not syntax failures. Comparisons ignore only bare local callee names in captured V8 TypeError messages, so renaming a local variable does not create a false behaviour mismatch. All raw observations are retained. The failed fixtures are preserved for later repair in new versions or exclusion.

The v5 batch tests Undici idle-socket gating, Vite trailing-slash deny checks, Fastify MIME essence parsing, Parse Server pointer permissions and metadata auth/error handling, Electron feature-option filtering, Minimist constructor traversal, and Nodemailer address control characters. [Exact-fix helper snapshots](../frozen/helper-context-v2/README.md) supply Electron coercion/parser/allowlist declarations and the Minimist prototype guard. Node supplies the real punycode conversion, bound by the recorded Node version.

The five newly failed transformations are L099 and L105 (swallow trigger rejection), L168 and LN174 (self-reference a local before initialization), and L277 (checks safe paths before the deny rule). Raw observations are retained. L139 and L159 pass after accounting for renamed locals in V8 error text. The v5 comparison additionally normalizes local receiver names in member-call TypeErrors and local source names in destructuring TypeErrors; it retains property names, null/undefined distinctions, error kinds and all other observations. Tests guard against hiding those differences.

The v6 batch tests Vite HTML middleware traversal/access checks, LiquidJS root lookup and fallback containment, Axios protocol-relative URL classification, Electron current-preference access checks, and Fastify body-schema selection with its exact matching MIME helper. It runs actual generator methods, including TypeScript class-method syntax. Pure preference-read ordering is not treated as a failure; configured values and returned authorization decisions are checked. L136 and LN141 incorrectly continue validation after an error, and LN286 calls an undefined error callback.

The v7 batch tests Undici cookie domains and unparsed cookie attributes, plus Axios proxy bypass and stale proxy credentials on redirects. [Pinned helper context](../frozen/helper-context-v3/README.md) records the real character validators, date helpers and proxy bypass logic. Cases include all byte-valued domain/value characters, header-name case variants, ordinary inputs and error controls. The corpus candidate itself is executed alongside both originals; the intended security witness must distinguish the originals before a candidate can pass. Some surrounding services are explicitly stubbed, so these results establish the recorded boundaries rather than universal equivalence or complete package exploitability.

The cookie controls exposed two transport issues: Windows default text decoding and `str.splitlines()` splitting raw Unicode U+0085/U+2028/U+2029 inside valid JSON strings. The new UTF-8 execution provider and v2 JSONL reader fix them without editing prior sealed code. The corrected batch preserves every validation record from the initial run, and now resumes with all hashes and checkpoint times unchanged. Use the v2 runner for future batches inheriting this Unicode evidence.

## Reproduce

```powershell
.venv/Scripts/python.exe -m eval.tier2.extend_validation --previous eval/frozen/revalidation-v5 --suite eval.tier2.routing_checks --output eval/frozen/revalidation-v6 --resume
.venv/Scripts/python.exe -m eval.tier2.extend_validation_v2 --previous eval/frozen/revalidation-v6 --suite eval.tier2.header_checks --output eval/frozen/revalidation-v7-utf8 --resume
```

For a fresh independent run of the latest batch, use a new empty directory and omit `--resume`. For the latest batch, use the v2 runner and explicitly specify `--previous eval/frozen/revalidation-v6 --suite eval.tier2.header_checks` (the CLI defaults still select the older v3 batch). The previous report's recorded evidence and inputs are verified before inheritance; no LLM inference is invoked. A sealed lock binds inputs, validation code, Node and parser versions; mismatches refuse resume. The existing frozen manifest is verified before and after execution.

Future batches should use `eval.tier2.extend_validation_v2 --previous eval/frozen/revalidation-v7-utf8 --suite eval.tier2.your_new_suite` with a new output directory. Put a new suite in new versioned source files: it must expose `HARNESSES`, `SCRIPT`, `selected(entry)` and `check(record, entry, entries)`, following `header_checks.py`. Additional imported source dependencies must be listed in `SUPPORT_FILES`. Leave prior sealed code and evidence intact. This supports adding tests; it does not automatically invent the missing tests or import human review decisions.

```powershell
.venv/Scripts/python.exe -m pytest tests/test_validation_unicode_jsonl.py tests/test_header_boundaries.py tests/test_routing_boundaries.py tests/test_permission_boundaries.py tests/test_context_boundaries.py tests/test_additional_boundaries.py tests/test_validation_extension.py tests/test_corpus_revalidation.py tests/test_frozen_ablation.py tests/test_candidate_gate.py tests/test_candidate_language.py tests/test_llm_transform.py tests/test_evaluation_metrics.py tests/test_tier1_targets.py -q
```
