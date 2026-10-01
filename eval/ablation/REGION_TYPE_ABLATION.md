# Region-type ablation after containment removal

Run these commands from the repository root. This study uses the current detector
and writes a new source/configuration lock. It reuses the verified reference,
reviewed cases, split, model bytes and embedding vectors from
`experiment-active-v2`; it does not resume the old detector experiments.

## Run

```powershell
# Read-only input and configuration checks; no model loading or inference.
.\scripts\run_region_type_ablation.ps1 -Plan

# Optional end-to-end pilot: 12 stratified cases, six arms, one repetition.
# Automatically uses a separate ...-smoke-12 output directory.
.\scripts\run_region_type_ablation.ps1 -SmokeLimit 12 -Repetitions 1

# Main study: all six arms, three repetitions, 1,200 cases per pass.
.\scripts\run_region_type_ablation.ps1

# Repeating the same command resumes unfinished cases and skips completed passes.
.\scripts\run_region_type_ablation.ps1

# Regenerate reports from completed passes without loading the model.
.\scripts\run_region_type_ablation.ps1 -CollectOnly
```

To run smaller batches, add `-Count 2`: each invocation completes the next two
unfinished arms. Keep repetitions, tier, split and output the same when resuming.
Use a different output directory when changing those settings or source files.
For a Tier 2-only study, use `-Tier tier2 -Output
eval/frozen/active-region-ablation-tier2-gpu-v1` consistently on every invocation.

The default main study requires 21,600 measured detector calls: 6 settings x 1,200
cases x 3 repetitions. Warmup calls are additional and excluded from timing.
The pilot is only a compatibility check; use the full run for report findings.
CUDA is required for scans. There are no LLM requests, hosted AI calls, Semgrep
scans or new reference embeddings. Keep other GPU workloads idle during timing.

## Controlled comparison

| Arm | Changed | Block | Context | Function | What it tests |
|---|---|---|---|---|---|
| `all_types` | Yes | Yes | Yes | Yes | Fresh control for this implementation |
| `no_changed` | No | Yes | Yes | Yes | Contribution of the smallest extracted regions |
| `no_block` | Yes | No | Yes | Yes | Contribution of enclosing blocks |
| `no_context` | Yes | Yes | No | Yes | Contribution of surrounding line context |
| `no_function` | Yes | Yes | Yes | No | Contribution of whole-function retrieval |
| `function_only` | No | No | No | Yes | Whether function retrieval alone is sufficient here |

All settings retain K5/B10, R96/V3, the 0.70 structural/token gates, 0.90 edit-side
threshold and 0.10 margin. Hashing and contrastive edit verification remain on;
local correspondence and LLM review remain off. GPU embeddings use FP32, TF32 is
disabled, and the model revision and sequence limit remain frozen.

Candidate eligibility is applied **before** the 96-region cap. Removed types
cannot consume that cap. The existing priority order and function insertion are
preserved. Function-only generates just the eligible function region.
When functions are excluded, the slot normally reserved for the function is
available to another eligible region; the overall cap remains 96.

Reference eligibility is applied **during** FAISS HNSW search with an ID selector,
before top-K result selection. Filtering a completed top-K result afterward would
unfairly discard slots; this runner does not do that. Both vulnerable and patched
vectors of an excluded type become ineligible. Full reference function pairs are
still available for patch-local diagnostics and verification in every arm.

The HNSW graph, vector values and row IDs stay fixed. Search may traverse excluded
nodes, but they cannot be returned. This isolates region eligibility without
rebuilding the approximate-search graph. It does **not** measure the memory,
construction time or exact latency of a separately rebuilt smaller production
index. Timings include candidate extraction and GPU encoding, search and
verification, with CUDA completion synchronized; setup, warmup and file IO are
excluded. The accelerated edit adapter has the same edit costs and scores as the
original dynamic program.

## Read the results

The main outputs are under `eval/frozen/active-region-ablation-gpu-v1/combined/`:

- `tables.md`: Tier 2 overall and fixed non-hash comparisons, with tuning and
  evaluation tables separate.
- `summary.json`: all Tier 1/Tier 2/combined, split and hash-route scopes; quality
  counts, completed repetitions and median measured detector time.
- `case-changes.json`: candidate-level decision/rank changes against `all_types`.

Each first-repetition checkpoint retains the detector result for inspection.
Later repetitions measure timing and must match the first decision/rank signature.
Quality cases are counted once, so three repetitions do not triple the sample size.
Checkpoint seals and the study lock prevent mixing changed code, inputs or settings.
An OS-backed writer lock rejects simultaneous runs against the same output.
Interrupted passes record their sessions; summed detector time is not uninterrupted
wall-clock throughput.

Primary interpretation should use **Tier 2 evaluation / non-hash** and the
corresponding overall Tier 2 evaluation results. The non-hash case IDs are fixed
using the unchanged hash lookup before any arm runs. Hash cases must keep the
same decisions across settings and serve as a route sanity check. Tier 1 largely
uses hashing, so its overall recall alone cannot establish that regions matter.

Compare correct-origin automatic recall, patched false alerts, manual-review
burden, retrieval ranking and runtime together. Inspect individual gains/losses
in `case-changes.json`; equal totals can hide different affected candidates.
Abstentions stay in the positive and patched denominators and are also reported
separately. Do not describe zero automatic alerts as zero review burden.

A loss after removing a type supports its contribution **in the presence of the
other three types under this fixed setting**. Unchanged totals support removal
only on these tested cases; inspect case changes and cost before recommending it.
Function-only tests the combined contribution of smaller regions. These six
settings do not establish the optimal subset or all interactions among types.

The 30/70 split is the existing retrospective grouped split, and expected origins
remain in the searchable corpus. Use tuning for a selection decision, then report
evaluation performance without further tuning. Prior development has already
used these cohorts, so this is not a pristine independent holdout or proof of
exploitability.
