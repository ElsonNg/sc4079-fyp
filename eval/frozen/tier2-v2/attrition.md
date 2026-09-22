# Validated Tier 2 cohort and attrition

Automated package-specific executable security litmus where supported; otherwise model source-and-patch review of the security delta with exact quoted evidence, supplemented by conservative AST preservation checks. No human validation claimed.

Second automated audit of extracted original security deltas, conservative literal/regex preservation screen, and paired re-admission. Never promotes rejected or unreviewed cases. Model clone classifications remain proposals unless mechanically confirmed.

Inputs: 788. Provisional admissions: 172. Final accepted: 60. Quarantined: 728. Packages: 10.

| Package | Accepted cases |
|---|---:|
| axios | 2 |
| liquidjs | 4 |
| lodash | 2 |
| moment | 4 |
| nuxt | 4 |
| parse-server | 10 |
| qs | 24 |
| semver | 4 |
| undici | 2 |
| vite | 4 |

| Expansion package | Selected origins / 10 | Accepted origins | Accepted cases / 40 |
|---|---:|---:|---:|
| axios | 10 | 1 | 2 |
| lodash | 4 | 1 | 2 |
| minimist | 4 | 0 | 0 |
| moment | 4 | 1 | 4 |
| nodemailer | 9 | 0 | 0 |
| qs | 9 | 8 | 24 |
| semver | 1 | 1 | 4 |
| undici | 10 | 1 | 2 |

All accepted cases are vulnerable/patched pairs per requested category. Requested Type 3/4 does not imply confirmed Type 3/4.
Source adjudications and per-case preservation reviews are automated, not human validation. Executable tests are bounded litmus tests, not general equivalence proofs.
Legacy generation model string only; original digest, prompts, attempts unavailable. Not retroactively inferred.

See validation.jsonl, adjudication.jsonl, source-adjudications.jsonl, and attrition.json for exact evidence, reasons, classifications, and provenance.
