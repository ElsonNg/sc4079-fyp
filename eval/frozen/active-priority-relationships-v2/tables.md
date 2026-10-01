# Experimental priority replay

Exploratory aggregation replay; original evidence/verdicts retained. No GPU inference or new timing. Informational does not mean globally safe.

With a verified patched boundary: connected revisions retain review, even below the edit-side threshold. Other review-causing alternatives retain review unless their identity is explicitly incompatible (different known code families, conflicting function identity, no broader correspondence, and both edit anchors explicitly generic). Missing edges, different paths, unknown identity and low scores alone do not establish incompatibility. Existing S/T-failed noise handling remains, except when an exact revision connection makes it relevant. Hash decisions, verified vulnerable findings and conflict handling are preserved. Cases without a verified patch retain the original policy.

## Tier 2 / tuning

| Regions | Correct origin (unchanged) | False alerts (unchanged) | Reviews before → after | Patched released | Vulnerable released | Protected reviews retained |
|---|---:|---:|---:|---:|---:|---:|
| all_types | 81/91 | 6/87 | 33 → 33 | 0 | 0 | 0/0 |
| no_changed | 81/91 | 5/87 | 29 → 31 | 0 | 0 | 0/0 |
| no_block | 79/91 | 4/87 | 34 → 36 | 0 | 0 | 0/0 |
| no_context | 81/91 | 6/87 | 32 → 32 | 0 | 0 | 0/0 |
| no_function | 75/91 | 3/87 | 38 → 40 | 0 | 0 | 0/0 |
| function_only | 78/91 | 5/87 | 23 → 23 | 0 | 0 | 0/0 |
| block_function | 81/91 | 5/87 | 31 → 31 | 0 | 0 | 0/0 |

## Tier 2 / evaluation

| Regions | Correct origin (unchanged) | False alerts (unchanged) | Reviews before → after | Patched released | Vulnerable released | Protected reviews retained |
|---|---:|---:|---:|---:|---:|---:|
| all_types | 178/210 | 13/212 | 85 → 85 | 0 | 0 | 0/0 |
| no_changed | 185/210 | 12/212 | 65 → 65 | 0 | 0 | 0/0 |
| no_block | 174/210 | 14/212 | 100 → 100 | 0 | 0 | 0/0 |
| no_context | 184/210 | 14/212 | 84 → 84 | 0 | 0 | 0/0 |
| no_function | 163/210 | 13/212 | 100 → 100 | 0 | 0 | 0/0 |
| function_only | 179/210 | 11/212 | 59 → 59 | 0 | 0 | 0/0 |
| block_function | 185/210 | 12/212 | 73 → 73 | 0 | 0 | 0/0 |

## Tier 2 / all

| Regions | Correct origin (unchanged) | False alerts (unchanged) | Reviews before → after | Patched released | Vulnerable released | Protected reviews retained |
|---|---:|---:|---:|---:|---:|---:|
| all_types | 259/301 | 19/299 | 118 → 118 | 0 | 0 | 0/0 |
| no_changed | 266/301 | 17/299 | 94 → 96 | 0 | 0 | 0/0 |
| no_block | 253/301 | 18/299 | 134 → 136 | 0 | 0 | 0/0 |
| no_context | 265/301 | 20/299 | 116 → 116 | 0 | 0 | 0/0 |
| no_function | 238/301 | 16/299 | 138 → 140 | 0 | 0 | 0/0 |
| function_only | 257/301 | 16/299 | 82 → 82 | 0 | 0 | 0/0 |
| block_function | 266/301 | 17/299 | 104 → 104 | 0 | 0 | 0/0 |

## Interpretation

A vulnerable-labelled case released from review is a risk even when its saved vulnerable verdict was already inconclusive. Unchanged automatic recall does not establish safety: this policy cannot alter automatic vulnerable findings by construction. Changes were selected after inspecting these retrospective cases; independent validation is needed before adoption. Replay timing excludes inference and is not a detector speed measurement.

## Revision relationships

16 exact patched-to-vulnerable links in the shared corpus. Connections establish equal source revisions, not a complete chronology or Git ancestry.

Relationship diagnostics for each case are in `relationship-traces.json`. Connected revisions and unknown alternatives may overlap within a case.

Block/function tuning: review-relevant boundary counts {'unknown': 32}.
Block/function evaluation: review-relevant boundary counts {'connected_revision': 3, 'unknown': 43}.
Block/function all: review-relevant boundary counts {'connected_revision': 3, 'unknown': 75}.
