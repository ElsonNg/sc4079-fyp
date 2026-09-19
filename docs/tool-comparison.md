# ProvTrail tool comparison

Evaluation date: 2026-09-19. The expanded benchmark contains 50 vulnerability
origins and 300 blinded cases: vulnerable/patched pairs in real-source,
detached-clone, and dependency-metadata arms. JavaScript and TypeScript each
contribute 25 origins.

## Locked tools

- Semgrep 1.177.0 uses the complete pinned community `javascript` and
  `typescript` directories at commit
  `40b8c63f75dc7c22c8a77482d73bfb864b146f7e`: 203 YAML files, 212 rule
  definitions, combined SHA-256
  `c795e1f388cb15cd5615e9f6d10e4e16985f4598cef70e5eee97b2a1a93e908c`.
- CodeQL 2.27.0 uses
  `codeql/javascript-queries:codeql-suites/javascript-security-extended.qls`.
  Every SARIF run is required to contain exactly 103 rule definitions.
- OSV-Scanner is pinned to 2.6.0.
- ProvTrail uses the production FP32 configuration with fallback disabled.

The machine-readable lock is in
[`eval/comparison_50_tool_lock.json`](../eval/comparison_50_tool_lock.json).

## Scoring and coverage controls

For Semgrep and CodeQL, any alert overlapping the labelled target path and line
span counts as a vulnerability detection. CWE alignment and advisory
attribution are reported separately and are not prerequisites for detection.
ProvTrail remains advisory-aware. OSV-Scanner is matched by the expected
advisory identity in the dependency-metadata arm.

Anonymous functions, class-method fragments, and function-body fragments are
wrapped into valid standalone CodeQL source. Target spans are recalculated after
wrapping. A separate CodeQL query verifies that an extracted function overlaps
every labelled span. An extraction miss is an execution/coverage failure, not a
false negative.

CodeQL extracted all 100 detached and all 100 real-source targets. Two
real-source labels were in Next.js's compiled `http-proxy/index.js`; CodeQL's
minified-file extractor override was required for those two targets. The final
evaluation has 100% execution coverage for every tool and 100% CodeQL target
extraction coverage.

As a configuration control, both static analyzers were run on a known command
injection fixture. Semgrep's `detect-child-process` rule and CodeQL's
`js/command-line-injection` rule both flagged only the vulnerable call on line
7; neither flagged the safe `execFileSync` implementation.

## Expanded results

Each scored arm contains 50 vulnerable and 50 patched cases.

| Tool | Arm | Vulnerable recall | Patched FPR | Advisory attribution | CWE alignment |
|---|---|---:|---:|---:|---:|
| ProvTrail | Real source | 47/50 (94%) | 2/50 (4%) | 49/100 | 49/100 |
| ProvTrail | Detached clone | 44/50 (88%) | 3/50 (6%) | 47/100 | 47/100 |
| Semgrep | Real source | 0/50 (0%) | 0/50 (0%) | 0/100 | 0/100 |
| Semgrep | Detached clone | 0/50 (0%) | 0/50 (0%) | 0/100 | 0/100 |
| CodeQL | Real source | 2/50 (4%) | 1/50 (2%) | 0/100 | 2/100 |
| CodeQL | Detached clone | 1/50 (2%) | 0/50 (0%) | 0/100 | 0/100 |
| OSV-Scanner | Dependency metadata | 50/50 (100%) | 1/50 (2%) | 51/100 | 0/100 |

CodeQL's real-source detections are a Vite path-injection case and a LiquidJS
sanitization case. The Vite alert is also present in the patched member, so the
rule does not distinguish that fix boundary. Its one detached detection is the
same LiquidJS sanitization vulnerability. Neither CodeQL nor Semgrep attributes
a benchmark alert to a specific advisory, as expected from general-purpose
static analysis.

ProvTrail's three real-source misses are in Nuxt `chunk.ts`, LiquidJS
`filters/html.ts`, and Fastify `validation.js`. CodeQL finds the LiquidJS case
that ProvTrail misses, demonstrating one complementary detection. ProvTrail's
two real-source false positives are the patched members of a Nuxt Nitro case
and a DOMPurify case.

OSV-Scanner detects every vulnerable dependency version. Its apparent patched
false positive is Fastify 5.3.2: the live OSV record now includes the benchmark
advisory's CVE/GHSA identity among a newer merged advisory's aliases. This is a
label/database-drift case rather than source-clone detection. OSV also reports
many unrelated advisories for the historical package versions; those are
retained as background alerts.

## Conclusion

The expanded result supports a scoped claim: on these 50 labelled source-level
vulnerability origins, ProvTrail identifies substantially more vulnerable reuse
than the pinned Semgrep community rules and CodeQL security-extended suite.
CodeQL remains complementary rather than uniformly weaker because it finds one
real-source vulnerability missed by ProvTrail. OSV-Scanner is highly effective
when package identity and version metadata are available, but it does not test
source-level clone recognition and produces substantial unrelated advisory
output on the historical dependency versions.

Full per-case results and coverage counts are in
[`eval/comparison_50_summary.json`](../eval/comparison_50_summary.json).
