# Experimental aggregation replay

This experiment tests `patch_specific_uncertainty_v1` against the completed
six-setting region ablation and block/function follow-up. It reads sealed
first-repetition checkpoints and completion markers, verifies their study and
candidate identities, checks source/input hashes, reproduces baseline priorities
and scope metrics, then changes only the proposed overall priority.

## Policy specified before replay

- Hash decisions and all verified vulnerable findings retain the existing policy.
- Without a verified patched boundary, retain the existing policy.
- With a verified patched boundary, preserve reviews caused by contradictions,
  contrastive conflicts or ambiguous hashes.
- Another uncertain boundary forces review only with medium/high lineage
  confidence, structural/token correspondence, and an explicitly identifying
  edit anchor whose corresponding side meets the existing edit threshold (0.90).
- Otherwise report informational lineage. Keep every uncertain boundary visible.

The anchor requirement is a proxy for correspondence to a particular patch.
It does not prove origin or exploitability. Function-name matching alone does
not qualify, and unknown anchor identity is not treated as positive identity.
All boundary verdicts, thresholds and retrieval evidence remain unchanged.

## Run

```powershell
.venv\Scripts\python.exe -m eval.ablation.run_priority_replay
```

Default output: `eval/frozen/active-priority-replay-v1/`. Use `--output` with a
fresh directory for a rerun; existing results are never overwritten.

- `tables.md`: scope comparisons and limitations.
- `summary.json`: baseline/replay metrics and source provenance.
- `case-changes.json`: each changed priority with its unchanged boundary states.

Quality is counted once. This performs no inference and produces no new detector
timing. It does not modify the production priority rule or original studies.

## Decision criteria

Count patched-labelled cases released from review, vulnerable-labelled cases
released from review, new reviews, and preserved conflict reviews. A vulnerable
release is a risk even when automatic recall is unchanged: unchanged automatic
findings are guaranteed by this policy's construction. Informational priority
does not mean globally safe. Any vulnerable releases require case inspection
before adoption, and zero releases on these cases would still require independent
validation. This exploratory policy was motivated by inspection of the same
retrospective cohorts, so it is not a holdout confirmation.
