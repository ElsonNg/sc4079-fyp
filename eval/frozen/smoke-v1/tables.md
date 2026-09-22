# Frozen ablation results

Counts show numerator/denominator. Tiers are separate. No winner is selected.

| Config | K | Budget | Edit score | Margin | Structure | Token | Retrieval |
|---|---:|---:|---:|---:|---:|---:|---:|
| 7c4923733a | 10 | 10 | 0.9 | 0.1 | 0.7 | 0.7 | 0.0 |
| 8ec8d76916 | 1 | 10 | 0.9 | 0.1 | 0.7 | 0.7 | 0.0 |

| Config | Tier / split | Retrieved | Visible | Correct origin / vulnerable | Wrong origin / all | Patched FP / patched | Abstained / all | Hash retrieval | Non-hash retrieval | Seconds |
|---|---|---|---|---|---|---|---|---|---|---|
| 7c4923733a | tier1 / tuning | 1/1 | 1/1 | 0/0 | 0/1 | 0/1 | 0/1 | 1/1 | 0/0 | 0.016 |
| 7c4923733a | tier2 / tuning | 7/7 | 7/7 | 5/5 | 4/7 | 0/2 | 1/7 | 0/0 | 7/7 | 62.831 |
| 8ec8d76916 | tier1 / tuning | 1/1 | 1/1 | 0/0 | 0/1 | 0/1 | 0/1 | 1/1 | 0/0 | 0.006 |
| 8ec8d76916 | tier2 / tuning | 7/7 | 7/7 | 5/5 | 4/7 | 0/2 | 1/7 | 0/0 | 7/7 | 62.957 |

Conditional rates exclude manual-review abstentions; all-labelled rates include them.

| Config | Tier / split | Conditional correct-origin recall | Conditional patched FP | Correct-origin detections / all labelled | Patched FP / all labelled |
|---|---|---|---|---|---|
| 7c4923733a | tier1 / tuning | 0/0 | 0/1 | 0/1 | 0/1 |
| 7c4923733a | tier2 / tuning | 5/5 | 0/1 | 5/7 | 0/7 |
| 8ec8d76916 | tier1 / tuning | 0/0 | 0/1 | 0/1 | 0/1 |
| 8ec8d76916 | tier2 / tuning | 5/5 | 0/1 | 5/7 | 0/7 |

Tuning non-dominated configurations (tier1): 8ec8d76916
Objectives: increase correct-origin detections; reduce patched FP, wrong attribution, abstentions, and measured runtime. Runtime is sensitive to warm-up and system load.

| Config | Correct-origin count delta | Patched FP count delta | Abstention count delta | Runtime delta (s) |
|---|---:|---:|---:|---:|
| 7c4923733a | 0 | 0 | 0 | 0.000 |
| 8ec8d76916 | 0 | 0 | 0 | -0.010 |

Tuning non-dominated configurations (tier2): 7c4923733a
Objectives: increase correct-origin detections; reduce patched FP, wrong attribution, abstentions, and measured runtime. Runtime is sensitive to warm-up and system load.

| Config | Correct-origin count delta | Patched FP count delta | Abstention count delta | Runtime delta (s) |
|---|---:|---:|---:|---:|
| 7c4923733a | 0 | 0 | 0 | 0.000 |
| 8ec8d76916 | 0 | 0 | 0 | 0.126 |
