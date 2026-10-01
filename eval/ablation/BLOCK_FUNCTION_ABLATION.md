# Block + function only

This follow-up runs exactly one new setting: `block_function`, with `changed`
and `context` excluded from candidate generation and reference search. It retains
K5/B10, R96/V3 and the existing verification thresholds, hashing and contrastive
edits. LLM review remains off.

```powershell
# Read-only validation.
.\scripts\run_block_function_ablation.ps1 -Plan

# Optional pilot in a separate output directory.
.\scripts\run_block_function_ablation.ps1 -SmokeLimit 12 -Repetitions 1

# Main run: one setting, 1,200 cases, three repetitions (3,600 measured calls).
.\scripts\run_block_function_ablation.ps1

# Resume using the same command, or rebuild reports without inference.
.\scripts\run_block_function_ablation.ps1 -CollectOnly
```

Results go to `eval/frozen/active-block-function-gpu-v1/combined/`:

- `tables.md`: the new setting and comparisons with the completed controls.
- `summary.json`: quality and timing scopes, plus reference provenance.
- `reference-case-changes.json`: paired changes against each saved control.

`all_types` is the existing four-type control: comparing against it shows the
effect of excluding changed and context together. `no_changed` is the existing
block/context/function setting: comparing against it shows the additional effect
of excluding context. These controls are read from the completed six-setting
study and are **not scanned again**. The original runner and completed results
remain unchanged.

The follow-up verifies matching data, model, dependencies, detector settings,
execution policy, code hashes, candidate identities and hash routes before
reusing the controls. Selected first-repetition control checkpoints are sealed
and their aggregate digest is included in the new study lock.
The GPU identity and CUDA/cuDNN runtime must also match before model loading.

Candidate and reference filtering follows the original ablation adapter:
eligibility before the candidate cap and before top-K reference selection. Full
functions remain available for patch verification. The HNSW graph is retained.
Checkpoint/resume and repeated-decision checks remain enabled. Only the new
setting has GPU measurements; saved and new timing come from separate sessions,
so timing comparisons are descriptive. Quality comparisons use the same cases.

Inspect Tier 2 evaluation and its fixed non-hash subset. Quality cases are counted
once; three repetitions measure timing and stability. Since the choice of this
follow-up was informed by the previous evaluation results, it is an exploratory
follow-up on the same retrospective cohorts, not independent confirmation.
