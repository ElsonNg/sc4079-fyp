# Tier 2 candidate admission decision

All 788 Tier 2 records have a case-level conservative admission decision. 442 are admitted: 388 retain v43 support and 54 gain static source-preservation evidence. The other 346 are not admitted: 88 failed prior recorded checks, 78 have excluded advisory/source labels, 14 have concrete source changes, five have earlier negative preservation reviews, and 161 have insufficient evidence for a generated-code preservation claim.

The 161 insufficient-evidence cases are **not** called invalid. They are withheld from the trusted candidate subset because structural edits remain unverified. Their complete source-to-candidate line diffs and static reasons are in the [v2 transformation audit](../tier2-transformation-static-audit-v2/README.md).

No exploit inputs were run. This decision does not alter v43 or recalculate pairing/clone-category eligibility.
