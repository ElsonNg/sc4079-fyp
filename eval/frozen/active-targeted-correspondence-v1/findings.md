# Targeted correspondence: findings

## Result

Simply adding direct function-to-function verification releases no snippets from
review. A different bounded structural comparison resolves three snippets: one
patched case and two vulnerable cases. This is a small exploratory gain, not a
general solution to the remaining review workload. Production stays unchanged.

| Tier 2 evaluation (422 cases) | Saved block/function | Direct function | Direct + bounded |
|---|---:|---:|---:|
| Correct-origin automatic detection | 185/210 | 185/210 | 186/210 |
| Patched false alerts | 12/212 | 12/212 | 12/212 |
| Manual reviews | 73 | 73 | 71 |
| Patched cases under review | 50 | 50 | 49 |
| Patched cases released from review | — | 0 | 1 |
| Vulnerable cases released without alert | — | 0 | 0 |

On the full 600-case Tier 2 cohort, the combined check changes reviews from
104 to 101 and correct-origin automatic detections from 266/301 to 268/301.
Patched false alerts remain 17/299. One new vulnerable alert is in tuning; one
new vulnerable alert and the patched release are in evaluation.

## What was different

104 initially reviewed snippets contained 453 eligible uncertain boundaries.
133 already had a complete candidate/reference function comparison; those
comparisons were not duplicated. 320 additional function comparisons were made
against the same retained boundaries, without another retrieval shortlist.
Direct comparisons change some boundary verdicts but do not resolve the final
review when other uncertainty remains.

The combined arm uses an existing optional experimental recognizer that was
disabled in the original study. It checks supported whole-function forms,
including guards, operation ordering and returned regexes. Unsupported forms,
normal-form mismatch and low function scores remain inconclusive; they do not
reject a boundary. It is not general semantic equivalence.

## The three resolved snippets

- **T2-ea9b0751bdb67c5fdb71 (tuning, vulnerable-labelled):** a rewritten Lodash
  `safeGet` retains the vulnerable guard behaviour. Whole-function guard
  correspondence produces a correct-origin vulnerability alert.
- **A2-a20a442675880a9f7ae5 (evaluation, vulnerable-labelled):** LiquidJS
  `readProperty` retains the nil check before `toLiquid`; the ordering recognizer
  identifies the vulnerable reference and produces a correct-origin alert.
- **A2-96fda452fca65af49e77 (evaluation, patched-labelled):** the corresponding
  LiquidJS candidate places `toLiquid` before the nil check. The ordering
  recognizer identifies the patched reference, releasing manual review.

L034 and LN018 both retain manual review. No original target boundary or
established vulnerable/patched verdict is removed or overwritten.

## Validation and limitations

155 relevant tests passed. Source identities, checkpoint seals and all baseline
metrics were verified. An independent audit recomputed all 48 reported scopes
from the saved checkpoints and changed results, checked unchanged targets and
established verdicts, and confirmed preserved hash priorities and L034/LN018
reviews. All three final priority changes were inspected against their captured
reference sources. No new false alerts or vulnerable releases without alerts
occurred on this cohort.

No GPU inference, new retrieval or candidate execution occurred. Additional
checks took about 5.3 CPU seconds per arm in this run, excluding checkpoint/model
deserialization outside the timed calls; this is not new end-to-end detector
timing. Stored detector timings are baseline values only. These retrospective
cases informed the experiment. Independent validation is needed before adoption.
