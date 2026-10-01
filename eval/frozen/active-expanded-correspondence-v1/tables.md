# Expanded whole-function correspondence

Exploratory CPU verification experiment. Same 1,200 cases and existing boundaries; no retrieval, GPU inference or candidate execution. Original detector timing retained only for baseline comparability, not new detector timing.

All arms first reproduce the previous bounded comparison. Expanded arms add whole-function AST correspondence that preserves lexical binding relationships, operations, control flow, free identifiers, property keys and literals. The noop arm additionally removes the exact statically false void branch. A full-function S/T gate must pass; supported correspondence to one distinct reference side can decide an existing uncertain boundary. Mismatch never rejects a boundary. All original targets and established verdicts remain.

## Tier 2 / tuning

| Check | Correct origin | Patched false alerts | Reviews before -> after | Patched released | Vulnerable newly alerted | Vulnerable released without alert |
|---|---:|---:|---:|---:|---:|---:|
| bounded_baseline | 82/91 | 5/87 | 31 -> 30 | 0 | 1 | 0 |
| expanded_ast | 83/91 | 5/87 | 31 -> 28 | 1 | 2 | 0 |
| expanded_ast_noop | 83/91 | 5/87 | 31 -> 28 | 1 | 2 | 0 |

## Tier 2 / evaluation

| Check | Correct origin | Patched false alerts | Reviews before -> after | Patched released | Vulnerable newly alerted | Vulnerable released without alert |
|---|---:|---:|---:|---:|---:|---:|
| bounded_baseline | 186/210 | 12/212 | 73 -> 71 | 1 | 1 | 0 |
| expanded_ast | 193/210 | 12/212 | 73 -> 62 | 3 | 8 | 0 |
| expanded_ast_noop | 193/210 | 12/212 | 73 -> 62 | 3 | 8 | 0 |

## Tier 2 / all

| Check | Correct origin | Patched false alerts | Reviews before -> after | Patched released | Vulnerable newly alerted | Vulnerable released without alert |
|---|---:|---:|---:|---:|---:|---:|
| bounded_baseline | 268/301 | 17/299 | 104 -> 101 | 1 | 2 | 0 |
| expanded_ast | 276/301 | 17/299 | 104 -> 90 | 4 | 10 | 0 |
| expanded_ast_noop | 276/301 | 17/299 | 104 -> 90 | 4 | 10 | 0 |

## Limits

Whole-function AST correspondence is an experimental copied-structure check, not general semantic equivalence. It handles specific documented normalizations and abstains on unsupported code. Existing guard/order/regex recognition remains the bounded baseline. Labels select no decisions and no thresholds were tuned here. Whole-function mismatch is not proof of unrelated origin. Retrospective results need independent controls before adoption. No production code or original result files were changed.
