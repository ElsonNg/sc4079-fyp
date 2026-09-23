# Active validated evaluation inputs

Both active tiers contain **exactly 600 valid cases**. Tier 1 has 300
vulnerable and 300 fixed release labels. Its reference snapshot contains the
original 301 entries plus 26 advisory- and npm-release-confirmed replacement
functions. The default Tier 1 release evaluator reads
`tier1_release_labels.jsonl` and `corpus.db` from this directory.

Tier 2 starts from 602 verified candidates. Two pair-ineligible cases with
the same candidate source (`L101` and `L110`) were omitted, leaving exactly
600 active cases. The removed case IDs and reason are recorded in
`tier2_pruned.jsonl`. All **247 complete eligible pairs (494 cases)** remain
in `tier2_eligible_pairs.jsonl`. The other 106 active Tier 2 cases are valid
individual candidates but do not meet the paired-experiment rule.

`summary.json` and `lock.json` give the current counts and file digests.
The historical frozen evaluations and their input files remain unchanged.

Regenerate the active inputs from the pinned evidence with:

```powershell
$env:PYTHONPATH='src;.'
.venv/Scripts/python.exe -m eval.active.build
```
