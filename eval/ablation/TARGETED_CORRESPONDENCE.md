# Targeted correspondence experiment

This experiment tests whether a different comparison can resolve an already
evaluated boundary. It uses the saved block/function study and its same 1,200
cases. Production code, frozen results and thresholds remain unchanged.

## Why this differs from repeating verification

The original edit stage already uses the whole snippet. Original S/T evidence
comes from shortlisted candidate/reference regions and may lack a complete
function-to-function comparison for a particular boundary. Add that comparison
explicitly without retrieval, and avoid duplicating one already present.

The second arm also uses the existing optional bounded correspondence checker
(`local_correspondence.py`, disabled in the original study). It compares supported
whole-function forms, including guards, operation ordering and returned regexes.
It can confirm correspondence to one reference side despite a fuzzy edit score
remaining inconclusive. It is not general semantic equivalence.

## Arms and controls

- `direct_function`: add at most one missing complete-function comparison per
  credible uncertain boundary in an initially reviewed snippet; classify using
  the same S/T/edit thresholds. This adds verification work beyond original V3,
  while retaining the original target boundaries and retrieval result.
- `direct_plus_bounded`: after the direct check, use the bounded recognizer only
  if complete-function S/T correspondence passes, the boundary remains uncertain
  and there is no conflict or identity rejection. Decisive recognizers must agree.

Confirmed vulnerable/patched states, hash decisions and explicit conflicts stay
unchanged. Every original boundary stays in the final result. Missing reference
metadata, low complete-function scores, unsupported structures or normal-form
mismatches do not establish unrelatedness. The resulting states are combined
using the conservative revision-relationship policy.

## Run

```powershell
.venv\Scripts\python.exe -m eval.ablation.run_targeted_correspondence
```

Use `--output` with a fresh directory for a rerun. Default output:
`eval/frozen/active-targeted-correspondence-v1/`.

- `tables.md`: paired scope metrics and released/alerted cases.
- `summary.json`: source/checkpoint hashes, metrics and additional CPU check time.
- `boundary-traces.json`: complete-function scores, prior comparison availability
  and bounded recognizer decisions for each attempted boundary.
- `case-changes.json`: changed boundary states, snippet priorities and results.

No GPU/model inference, new retrieval or candidate-code execution occurs.
Original detector seconds in scope metrics are baseline values, not measurements
of a new end-to-end run. Additional CPU check seconds are reported separately.
The exact edit accelerator preserves original scoring and costs. Candidate labels
affect only metrics, not decisions or which cases are checked.

## Interpretation

Separate boundary resolutions from final snippet resolutions. A boundary may
become patched while a different retained boundary still causes review. Count
new false alerts, vulnerable cases released without alerts, correct-origin alert
gains and patched review releases. Check intermediate revisions such as L034 and
weak alternatives such as LN018. Since these retrospective cases informed the
experiment, independent validation is required before adoption.
