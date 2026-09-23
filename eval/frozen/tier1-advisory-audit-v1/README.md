# Tier 1 advisory validity audit

This is a **source-and-advisory validity** decision for all 600 Tier 1 labels, separate from the earlier exploit/security-boundary validation. It does not run package exploits. It compares each labelled release target with the frozen vulnerable or patched function, the cited advisory and fix commit, the package/repository/file/language identity, and the advisory's fixed-version list.

| Advisory-level verdict | Cases | Meaning |
|---|---:|---|
| Valid exact advisory reference | 532 | Exact target/reference source hash, matching advisory and fix identity, and a consistent vulnerable/fixed version side. Includes 178 cases previously pending only for security-boundary evidence. |
| Valid release-specific reference | 16 | Target hash matches historical release source; its before/after change matches the cited fix despite differing from the fix-commit extraction. Four `ws` sources were fetched from immutable release commits and hash-pinned. |
| Excluded security label | 50 | Exact patch artifact, but prior line review found the extraction nonrepresentative or unsuitable as a standalone security-labelled source. |
| Excluded incompatible release pair | 2 | Multer release snippets are different callbacks with incompatible signatures. |

All 300 cleared versions exactly match an advisory-listed fixed version. All 300 flagged versions are absent from that fixed-version list. Every fix commit appears in the advisory references, and all 600 rows match advisory ID, package, repository, file path and language. **582 of 600** release target hashes match their labelled frozen reference exactly; the 50 prior exclusions are within those 582.

[Per-case decisions](cases.jsonl) contain the checks and hashes. [The 18 differing release sources](mismatches.md), [historical release pair diffs](release-specific-diffs.md), and [pinned `ws` release diffs](ws-release-diffs.md) show why 16 are valid and two are excluded. [Origin line diffs](origin-line-diffs.jsonl) bind the previously pending references to changed source lines; their complete numbered vulnerable, patched and candidate sources are linked per case in the decisions. [Summary](summary.json) and [file hashes](lock.json) make the audit reproducible.

The audit uses the project's frozen advisory and release-label snapshots plus four upstream `ws` source files fetched from immutable release commits. It does not re-fetch release tarballs or establish full-package exploitability. The v43 security-validation statuses remain sealed and unchanged; this report answers the narrower Tier 1 validity question.

```powershell
.venv/Scripts/python.exe -m eval.tier1.advisory_validity_audit
.venv/Scripts/python.exe -m pytest -q tests/test_tier1_advisory_validity_audit.py
```
