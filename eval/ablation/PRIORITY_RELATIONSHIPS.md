# Priority replay with revision relationships

This exploratory experiment implements `revision_relationship_uncertainty_v2`.
It retains the v1 policy and results for comparison and does not modify
production verification, thresholds or priority handling.

## Rules

Verified vulnerable findings, hash decisions and explicit conflicts retain their
existing handling. Cases without a verified patched finding retain the original
policy. When a patched finding exists:

1. Another uncertain boundary in the same connected revision component retains
   review, including below-threshold edit evidence.
2. A review-causing alternative with unknown relationship retains review.
3. A generic alternative can stop forcing review only with all these identity
   signals: different known code families with named reference functions,
   conflicting candidate/reference function identity, no broader correspondence,
   and both selected edit anchors explicitly lacking identifying tokens.

The third condition is a conservative operational proxy for incompatible
identity, not a proof of historical origin. Names or paths alone do not suffice.
Unknown anchor identity does not count as rejection. Existing S/T-failed weak
noise remains ignored unless a revision connection makes it relevant. Identity
rejection does not override conflicts. Individual boundary verdicts are unchanged.

## Revision connections

Connect boundary A to B when A's complete patched source exactly equals B's
complete vulnerable source within the same repository/file/function lineage and
language. Use connected components to protect alternative fixes in either
direction, including transitively. No dates or advisory order are used.
Same-lineage membership alone does not establish a revision edge. Missing edges
do not establish unrelatedness, and unknown boundaries remain unknown. These
connections do not claim complete Git history, commit ancestry or a unique time
of copying; branches and backports can share the same code revision.

## Run and assess

```powershell
.venv\Scripts\python.exe -m eval.ablation.run_priority_relationships
```

Use `--output` with a fresh directory for a rerun. Default output:
`eval/frozen/active-priority-relationships-v2/`.

- `tables.md`: before/after metrics for all seven region settings.
- `summary.json`: scope metrics, source provenance, exact revision links and
  hashes for the v1 reader, v2 adapter and v2 policy.
- `relationship-traces.json`: relevant alternatives, relationship classifications
  and review requirements per candidate/setting.
- `case-changes.json`: changed overall priorities and preserved boundary states.

The unchanged v1 checkpoint reader verifies source/input bytes, sealed checkpoint
identities, completion markers and baseline scope metrics. Each first-repeat
case is replayed once; no GPU inference or new detector timing is produced.
The expected-status labels are used only to count outcomes, not to make policy
decisions. Assess vulnerable releases, patched releases and additional reviews.
L034-style intermediate revisions must keep review. LN018-style alternatives
may remain unresolved when the saved evidence cannot establish incompatibility.
This policy was designed after inspecting these same retrospective cases, so
successful replay would still require independent validation before adoption.
