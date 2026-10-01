# Experimental priority replay

Exploratory aggregation replay; original evidence/verdicts retained. No GPU inference or new timing. Informational does not mean globally safe.

Only when a verified patched boundary exists: keep hash decisions and verified vulnerable findings unchanged; preserve contradiction, contrastive-conflict and hash-ambiguity reviews. Otherwise require medium/high lineage, S/T correspondence, and an explicitly identifying edit anchor on a side scoring at least the source study's existing edit-side threshold (0.90). Weaker alternatives remain recorded without forcing review. Cases without a verified patch retain the old policy.

## Tier 2 / tuning

| Regions | Correct origin (unchanged) | False alerts (unchanged) | Reviews before → after | Patched released | Vulnerable released | Protected reviews retained |
|---|---:|---:|---:|---:|---:|---:|
| all_types | 81/91 | 6/87 | 33 → 18 | 15 | 0 | 0/0 |
| no_changed | 81/91 | 5/87 | 29 → 18 | 11 | 0 | 0/0 |
| no_block | 79/91 | 4/87 | 34 → 22 | 12 | 0 | 0/0 |
| no_context | 81/91 | 6/87 | 32 → 18 | 14 | 0 | 0/0 |
| no_function | 75/91 | 3/87 | 38 → 24 | 12 | 2 | 0/0 |
| function_only | 78/91 | 5/87 | 23 → 22 | 1 | 0 | 0/0 |
| block_function | 81/91 | 5/87 | 31 → 18 | 13 | 0 | 0/0 |

## Tier 2 / evaluation

| Regions | Correct origin (unchanged) | False alerts (unchanged) | Reviews before → after | Patched released | Vulnerable released | Protected reviews retained |
|---|---:|---:|---:|---:|---:|---:|
| all_types | 178/210 | 13/212 | 85 → 53 | 31 | 1 | 0/0 |
| no_changed | 185/210 | 12/212 | 65 → 47 | 17 | 1 | 0/0 |
| no_block | 174/210 | 14/212 | 100 → 63 | 36 | 1 | 0/0 |
| no_context | 184/210 | 14/212 | 84 → 50 | 33 | 1 | 0/0 |
| no_function | 163/210 | 13/212 | 100 → 69 | 30 | 1 | 0/0 |
| function_only | 179/210 | 11/212 | 59 → 55 | 3 | 1 | 0/0 |
| block_function | 185/210 | 12/212 | 73 → 44 | 28 | 1 | 0/0 |

## Tier 2 / all

| Regions | Correct origin (unchanged) | False alerts (unchanged) | Reviews before → after | Patched released | Vulnerable released | Protected reviews retained |
|---|---:|---:|---:|---:|---:|---:|
| all_types | 259/301 | 19/299 | 118 → 71 | 46 | 1 | 0/0 |
| no_changed | 266/301 | 17/299 | 94 → 65 | 28 | 1 | 0/0 |
| no_block | 253/301 | 18/299 | 134 → 85 | 48 | 1 | 0/0 |
| no_context | 265/301 | 20/299 | 116 → 68 | 47 | 1 | 0/0 |
| no_function | 238/301 | 16/299 | 138 → 93 | 42 | 3 | 0/0 |
| function_only | 257/301 | 16/299 | 82 → 77 | 4 | 1 | 0/0 |
| block_function | 266/301 | 17/299 | 104 → 62 | 41 | 1 | 0/0 |

## Interpretation

A vulnerable-labelled case released from review is a risk even when its saved vulnerable verdict was already inconclusive. Unchanged automatic recall does not establish safety: this policy cannot alter automatic vulnerable findings by construction. Changes were selected after inspecting these retrospective cases; independent validation is needed before adoption. Replay timing excludes inference and is not a detector speed measurement.
