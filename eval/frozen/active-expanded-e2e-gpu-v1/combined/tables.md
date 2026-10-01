# Expanded verifier: GPU end-to-end detector evaluation

Block/function regions; retrieval top-K 5, verification budget 10, R96/V3; S/T 0.70, edit 0.90, margin 0.10.

CUDA FP32; hash and contrastive scoring enabled; expanded verifier enabled; LLM off. Fresh candidate embeddings, retrieval and verification run for every unfinished non-hash case. Reference vectors are reused; old candidate results are not reused.

Timing covers the detector pipeline, with CUDA synchronization; setup, warmup and checkpoint IO are excluded. It does not measure directory discovery, report rendering or rebuilding the reference index.

The corpus and retrospective tuning/evaluation split remain fixed. These cases have already informed development; this is a regression and runtime evaluation.

## tier1

| Split | Route | Repeats | Cases | Correct origin | Patched false alerts | Reviews | Median seconds |
|---|---|---|---:|---|---|---|---:|
| all | all | 3/3 | 600 | 300/300 (100.00%) | 13/300 (4.33%) | 0/600 (0.00%) | 2.57 |
| tuning | all | 3/3 | 181 | 90/90 (100.00%) | 6/91 (6.59%) | 0/181 (0.00%) | 0.39 |
| evaluation | all | 3/3 | 419 | 210/210 (100.00%) | 7/209 (3.35%) | 0/419 (0.00%) | 2.18 |

## tier2

| Split | Route | Repeats | Cases | Correct origin | Patched false alerts | Reviews | Median seconds |
|---|---|---|---:|---|---|---|---:|
| all | all | 3/3 | 600 | 276/301 (91.69%) | 17/299 (5.69%) | 90/600 (15.00%) | 107.66 |
| all | non_hash | 3/3 | 446 | 199/224 (88.84%) | 14/222 (6.31%) | 90/446 (20.18%) | 107.00 |
| tuning | all | 3/3 | 178 | 83/91 (91.21%) | 5/87 (5.75%) | 28/178 (15.73%) | 34.85 |
| tuning | non_hash | 3/3 | 131 | 60/68 (88.24%) | 5/63 (7.94%) | 28/131 (21.37%) | 34.70 |
| evaluation | all | 3/3 | 422 | 193/210 (91.90%) | 12/212 (5.66%) | 62/422 (14.69%) | 72.66 |
| evaluation | non_hash | 3/3 | 315 | 139/156 (89.10%) | 9/159 (5.66%) | 62/315 (19.68%) | 72.15 |

## combined

| Split | Route | Repeats | Cases | Correct origin | Patched false alerts | Reviews | Median seconds |
|---|---|---|---:|---|---|---|---:|
| all | all | 3/3 | 1200 | 576/601 (95.84%) | 30/599 (5.01%) | 90/1200 (7.50%) | 110.24 |
| all | non_hash | 3/3 | 446 | 199/224 (88.84%) | 14/222 (6.31%) | 90/446 (20.18%) | 107.00 |
| tuning | all | 3/3 | 359 | 173/181 (95.58%) | 11/178 (6.18%) | 28/359 (7.80%) | 35.24 |
| tuning | non_hash | 3/3 | 131 | 60/68 (88.24%) | 5/63 (7.94%) | 28/131 (21.37%) | 34.70 |
| evaluation | all | 3/3 | 841 | 403/420 (95.95%) | 19/421 (4.51%) | 62/841 (7.37%) | 75.00 |
| evaluation | non_hash | 3/3 | 315 | 139/156 (89.10%) | 9/159 (5.66%) | 62/315 (19.68%) | 72.15 |

Complete hash/non-hash metrics, retrieval ranks and timing scopes are in `summary.json`; first-pass checkpoints contain full boundary evidence.

Partial repetitions are excluded until complete. Interrupted repetitions retain their checkpoints and are marked in their completion metadata. Smoke runs are pilot checks.
