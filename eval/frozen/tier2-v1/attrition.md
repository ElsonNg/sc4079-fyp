# Tier 2 validation and attrition

Automated package-specific executable security litmus where supported; otherwise model source-and-patch review of the security delta with exact quoted evidence, supplemented by conservative AST preservation checks. No human validation claimed.

Legacy generation model string only; original digest, prompts, attempts unavailable. Not retroactively inferred.

Input cases: 788. Accepted: 172. Quarantined: 616. Accepted packages: 19.

| Missing package | Selected origins (maximum 10) | Accepted origins | Accepted cases (maximum 40) |
|---|---:|---:|---:|
| axios | 10 | 3 | 8 |
| lodash | 4 | 3 | 6 |
| minimist | 4 | 1 | 2 |
| moment | 4 | 1 | 4 |
| nodemailer | 9 | 2 | 6 |
| qs | 9 | 8 | 24 |
| semver | 1 | 1 | 4 |
| undici | 10 | 2 | 4 |

Cases are accepted only in vulnerable/patched pairs for each requested transformation category.
Requested and reviewed clone classifications are recorded separately. Quarantine includes duplicate sources, incomplete pairs, source identity failures, and uncertain reviews.
Diagnostic anchors are screening evidence only. Package-specific source-and-patch review is required even when anchors are absent (including qs).

See attrition.json for generation attempt failures and validation.jsonl for per-case review evidence and exclusions.
