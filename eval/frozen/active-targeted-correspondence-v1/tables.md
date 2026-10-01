# Targeted boundary correspondence

Exploratory CPU verification experiment. Same 1,200 cases and existing boundaries; no retrieval, GPU inference or candidate execution. Original detector timing retained only for baseline comparability, not new detector timing.

The direct arm adds missing function-to-function evidence to each credible uncertain boundary in an initially reviewed snippet, then uses the unchanged S/T/edit thresholds. The bounded arm also checks supported whole-function forms (guard/ordering/returned regex); positive reference-side correspondence can decide a boundary. Low scores, unsupported code and mismatches cannot reject a boundary. All original target boundaries and established verdicts are retained.

## Tier 2 / tuning

| Check | Correct origin | Patched false alerts | Reviews before -> after | Patched released | Vulnerable newly alerted | Vulnerable released without alert |
|---|---:|---:|---:|---:|---:|---:|
| direct_function | 81/91 | 5/87 | 31 -> 31 | 0 | 0 | 0 |
| direct_plus_bounded | 82/91 | 5/87 | 31 -> 30 | 0 | 1 | 0 |

## Tier 2 / evaluation

| Check | Correct origin | Patched false alerts | Reviews before -> after | Patched released | Vulnerable newly alerted | Vulnerable released without alert |
|---|---:|---:|---:|---:|---:|---:|
| direct_function | 185/210 | 12/212 | 73 -> 73 | 0 | 0 | 0 |
| direct_plus_bounded | 186/210 | 12/212 | 73 -> 71 | 1 | 1 | 0 |

## Tier 2 / all

| Check | Correct origin | Patched false alerts | Reviews before -> after | Patched released | Vulnerable newly alerted | Vulnerable released without alert |
|---|---:|---:|---:|---:|---:|---:|
| direct_function | 266/301 | 17/299 | 104 -> 104 | 0 | 0 | 0 |
| direct_plus_bounded | 268/301 | 17/299 | 104 -> 101 | 1 | 2 | 0 |

## Limits

The bounded recognizer is an existing optional experimental check, previously disabled. It is limited to supported structures and is not general semantic equivalence. Labels select no decisions and no thresholds were tuned here. Whole-function mismatch is not proof of unrelated origin. Retrospective results need independent controls before adoption. No production code or original result files were changed.
