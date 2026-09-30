# Findings and ablation: corrected hash-rule summary

Derived from saved evidence. Exact hashes take precedence within each fix boundary; shared abstracted hashes are ambiguous, not contradictory. Original frozen outputs remain unchanged.

No detector/model inference or API calls were made. Timings and repetitions remain historical.

## Recommended operating point

K5/B10, R96/V3; hashing and contrastive ON; containment OFF; LLM OFF.

| Tier | Automatic recall | Correct-origin recall | Precision | Patched FPR | Reviews |
|---|---|---|---|---|---|
| tier1 | 300/300 (100.00%) | 300/300 (100.00%) | 300/313 (95.85%) | 13/300 (4.33%) | 0/600 (0.00%) |
| tier2 | 264/301 (87.71%) | 259/301 (86.05%) | 264/283 (93.29%) | 19/299 (6.35%) | 118/600 (19.67%) |
| combined | 564/601 (93.84%) | 559/601 (93.01%) | 564/596 (94.63%) | 32/599 (5.34%) | 118/1200 (9.83%) |


Only the Next.js case T1-3279232376a64d7faba3 changes in each hash-enabled configuration. The no-hash component remains unchanged. The affected case is in tuning; all four parameter evaluation-partition results are unchanged.

## Reprojected LLM results

The corrected review population is 118 cases: 37 vulnerable-labelled and 81 patched-labelled. The removed case is now automatically classified, so its historical opinion no longer determines triage.

| Reviewer | Repeat | Auto/LLM recall | Origin recall | Precision | Patched FPR | Remaining reviews |
|---|---|---|---|---|---|---|
| qwen3 | 1 | 594/601 (98.84%) | 580/601 (96.51%) | 594/675 (88.00%) | 81/599 (13.52%) | 3/1200 (0.25%) |
| qwen3 | 2 | 594/601 (98.84%) | 580/601 (96.51%) | 594/674 (88.13%) | 80/599 (13.36%) | 3/1200 (0.25%) |
| qwen3 | 3 | 594/601 (98.84%) | 580/601 (96.51%) | 594/675 (88.00%) | 81/599 (13.52%) | 3/1200 (0.25%) |
| glm5 | 1 | 593/601 (98.67%) | 580/601 (96.51%) | 593/626 (94.73%) | 33/599 (5.51%) | 47/1200 (3.92%) |
| gemini | 1 | 593/601 (98.67%) | 580/601 (96.51%) | 593/627 (94.58%) | 34/599 (5.68%) | 41/1200 (3.42%) |
| gemini_pro | 1 | 592/601 (98.50%) | 579/601 (96.34%) | 592/627 (94.42%) | 35/599 (5.84%) | 44/1200 (3.67%) |


SAST/SCA comparison results and the containment stress-test results are unchanged; the saved copied-code replay checked 6,522 function findings and found no changed verdicts.

The headline results remain retrospective advisory-labelled recognition, not proof that each extracted function is independently exploitable. A fresh baseline under a new compatible freeze remains useful before presenting revised-code runtime or repeatability claims.

## Reproducibility

Run `.venv/Scripts/python.exe -m eval.recompute_hash_summaries`. Derived JSON files are under `eval/comparison_raw/hash-rule-summary-v1/`; verification.json binds input and code hashes.

Generate the PDF with `.venv/Scripts/python.exe scripts/build_findings_pdf.py` after recomputation. The builder requires ReportLab and pypdf; the original local frozen datasets and comparison artifacts are inputs, preserved separately from this patch. Neither script performs model inference or scanner/API calls.

## Component ablation (corrected first-pass quality)

### tier1

| Setting | Automatic recall | Origin recall | Patched FPR | Reviews |
|---|---|---|---|---|
| control | 300/300 (100.00%) | 300/300 (100.00%) | 13/300 (4.33%) | 0/600 (0.00%) |
| no_hash | 276/300 (92.00%) | 269/300 (89.67%) | 28/300 (9.33%) | 146/600 (24.33%) |
| no_containment | 300/300 (100.00%) | 300/300 (100.00%) | 13/300 (4.33%) | 0/600 (0.00%) |
| no_contrastive | 300/300 (100.00%) | 300/300 (100.00%) | 13/300 (4.33%) | 0/600 (0.00%) |


### tier2

| Setting | Automatic recall | Origin recall | Patched FPR | Reviews |
|---|---|---|---|---|
| control | 264/301 (87.71%) | 259/301 (86.05%) | 19/299 (6.35%) | 128/600 (21.33%) |
| no_hash | 258/301 (85.71%) | 250/301 (83.06%) | 23/299 (7.69%) | 161/600 (26.83%) |
| no_containment | 264/301 (87.71%) | 259/301 (86.05%) | 19/299 (6.35%) | 118/600 (19.67%) |
| no_contrastive | 241/301 (80.07%) | 231/301 (76.74%) | 19/299 (6.35%) | 188/600 (31.33%) |


## GPU parameter shortlist (evaluation; unchanged)

| Setting | Automatic recall | Origin recall | Patched FPR | Reviews |
|---|---|---|---|---|
| control | 183/210 (87.14%) | 178/210 (84.76%) | 13/212 (6.13%) | 88/422 (20.85%) |
| S0.80 | 181/210 (86.19%) | 176/210 (83.81%) | 13/212 (6.13%) | 82/422 (19.43%) |
| R64 | 183/210 (87.14%) | 174/210 (82.86%) | 12/212 (5.66%) | 87/422 (20.62%) |
| K5_B10 | 183/210 (87.14%) | 178/210 (84.76%) | 13/212 (6.13%) | 92/422 (21.80%) |


All 38 CPU tuning configurations now have Tier 1 origin recall 90/90, 6/91 patched alerts and zero reviews. Tier 2 CPU tuning results are unchanged. Hash-enabled full-cohort Tier 1 ablations now have 300/300 origin recall; the no-hash arm remains 269/300.

Removing containment retains the same automatic/false-alert sets and reduces full-cohort reviews from 128 to 118. K5/B10 remains the recommended balance; the R64 and S0.80 evaluation tradeoffs are unchanged.
