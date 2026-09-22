# Corpus revalidation

All input cases assessed. Validation means recorded bounded executable or source-review evidence, not proof of full package security. Unresolved cases remain excluded. Pair/duplicate eligibility is separate. No human validation, release refetch, new generation, freeze replacement, or full ablations.

| Tier | Candidates | Validated individually | Executable | Source review | Behaviour mismatch | Unresolved / source issues |
|---|---:|---:|---:|---:|---:|---:|
| tier1 | 600 | 136 | 56 | 80 | 0 | 464 |
| tier2 | 788 | 107 | 85 | 22 | 13 | 668 |

Tier 2 complete, unique, validated pairs: 86 cases (43 pairs).
These are proposed newly eligible fixtures, not a replacement of the active experiment-v2 freeze. Clone Type 3/4 claims remain unconfirmed.

## Per-package evidence

| Package | Tier 1 validated / total | Tier 2 validated / total | Tier 2 paired |
|---|---:|---:|---:|
| axios | 6 / 32 | 3 / 39 | 2 |
| better-auth | 2 / 14 | 0 / 22 | 0 |
| dompurify | 2 / 28 | 0 / 41 | 0 |
| electron | 2 / 22 | 0 / 44 | 0 |
| fastify | 2 / 14 | 1 / 21 | 0 |
| handlebars | 0 / 10 | 0 / 9 | 0 |
| liquidjs | 12 / 26 | 4 / 51 | 4 |
| lodash | 2 / 8 | 3 / 16 | 2 |
| mermaid | 2 / 24 | 0 / 23 | 0 |
| minimist | 4 / 8 | 6 / 16 | 4 |
| moment | 2 / 8 | 4 / 13 | 4 |
| multer | 2 / 14 | 0 / 21 | 0 |
| next | 2 / 22 | 3 / 29 | 2 |
| nodemailer | 6 / 18 | 3 / 28 | 2 |
| nuxt | 16 / 64 | 13 / 97 | 10 |
| parse-server | 30 / 102 | 21 / 157 | 14 |
| qs | 18 / 18 | 28 / 36 | 24 |
| semver | 2 / 2 | 4 / 4 | 4 |
| undici | 8 / 58 | 10 / 36 | 10 |
| validator | 4 / 6 | 0 / 6 | 0 |
| vite | 12 / 78 | 4 / 78 | 4 |
| ws | 0 / 24 | 0 / 1 | 0 |

## Recorded failures

Executable mismatches are relative to the explicit harness inputs and stubs. They do not establish exploitability of an entire package.

- L014 (parse-server): jwt_policy
- L020 (parse-server): jwt_policy
- L080 (next): framing
- LN022 (parse-server): jwt_policy
- LN028 (parse-server): jwt_policy
- LN033 (parse-server): jwt_policy
- LN037 (parse-server): jwt_policy
- LN088 (nuxt): redirect_url
- T2-65d63c5ad595201c7c63 (qs): qs-prototype-assignment
- T2-c0927aa1d2e95717a4c7 (qs): qs-prototype-assignment
- T2-cb6a1283e9ec86f30b72 (qs): qs-prototype-assignment
- T2-ef88cb816848e0f286ee (minimist): minimist-prototype-predicate
- T2-f70f5b3febb04d98b90f (minimist): minimist-prototype-predicate

See validation.jsonl for every case, exact observations, bound original/candidate hashes, diagnostics, prior source audits and unresolved reasons. checks.jsonl contains sealed resumable checkpoints; lock.json pins inputs, code and parser/Node versions.

Reproduce:

```powershell
.venv/Scripts/python.exe -m eval.tier2.revalidate --output eval/frozen/revalidation-v1 --resume
```
For an independent fresh run, use a new empty output directory and omit --resume.
