# Tier 1 expansion: 600 advisory-valid cases

The earlier 600-case Tier 1 audit admitted 548 cases and excluded 52. This
version adds **26 distinct vulnerable/fixed function pairs (52 cases)** from
21 advisory IDs. The combined manifest has **600 valid cases**. The 52
excluded original labels remain excluded and are not relabelled.

Each replacement pair has all of the following evidence:

- The official GitHub advisory lists the package and fixed version and cites
  the exact fix commit.
- The production JavaScript function changes in that commit. `pairs.jsonl`
  records the full before/after source, hashes, changed lines, and a short
  line-level explanation of why the change matches the advisory.
- The exact vulnerable function text occurs in the last affected npm release
  tarball, and the exact patched function text occurs in the first fixed npm
  release tarball. The tarballs and release files are SHA-256 pinned.
- No replacement origin or source pair duplicates the original corpus or
  another replacement.

This is the user's requested advisory/source validity standard. It does not
claim exploitability or run attack inputs. The npm release tarballs were
read-only inputs; the original corpus database, labels, and audit were not
modified.

`pairs.jsonl` is the full replacement evidence. `cases.jsonl` has the 52 new
case labels. `combined-valid-cases.jsonl` contains the 548 previously valid
labels plus the 52 replacements. `summary.json` contains the counts, and
`lock.json` pins the final files. Candidate extraction and release-check
results are kept in `../tier1-replacement-candidates-v1/` for review.

To regenerate the final manifests from the frozen candidate evidence:

```powershell
$env:PYTHONPATH='src;.'
.venv/Scripts/python.exe -m eval.tier1.build_replacement_manifest
```
