# Revision relationship policy: findings

## Result

The v2 replay preserves reviews for the vulnerable cases released by v1, but
does not release any patched case from review. It does not demonstrate a review
workload improvement. Keep production priority handling unchanged.

| Block + function, Tier 2 evaluation | Production baseline | Rejected v1 experiment | Relationship v2 |
|---|---:|---:|---:|
| Correct-origin automatic detection | 185/210 | 185/210 | 185/210 |
| Patched false alerts | 12/212 | 12/212 | 12/212 |
| Manual reviews | 73 | 44 | 73 |
| Patched cases released from baseline review | 0 | 28 | 0 |
| Vulnerable cases released from baseline review | 0 | 1 | 0 |

For the full 600-case Tier 2 block/function cohort, reviews remain 104; tuning
reviews remain 31. Quality is counted once per setting. No GPU inference or new
detector timing was performed.

## Concrete cases

- **L034:** the uncertain expected Nuxt boundary is exactly connected to the
  verified patched earlier boundary. V2 retains manual review despite its
  below-threshold edit score. All seven settings retain its review.
- **LN018:** the uncertain alternative is classified unknown, not unrelated.
  Saved correspondence to a different function does not supply the full identity
  rejection required by this policy. Block/function therefore retains review.
- **L240/L241:** the no-function setting retains review; v1 had released these
  vulnerable-labelled tuning cases.

## Other settings

All seven settings have unchanged evaluation priorities. The no-changed,
no-block and no-function settings each add two patched tuning reviews because
an exact revision connection makes a previously S/T-failed alternative relevant.
The affected candidates are LN136/LN144 in no-changed, and
T2-3b284f0c0740c36a694b/T2-4b4f622969b0807eebb2 in no-block and no-function.
These are six case-setting changes for four distinct candidate IDs.

Across all 8,400 case-setting traces, 26 relevant boundary observations were
classified connected, 467 unknown and one identity-incompatible. These counts
are observations across repeated settings, not independent candidates. The one
identity-incompatible alternative coexists with other review-requiring evidence,
so it does not release its candidate. The corpus contains 16 exact revision links.

## Validation and limits

84 relevant unit/integration tests passed. The replay verified sealed candidate
identities, completed source studies, input/source bytes, baseline priorities and
all 168 baseline scopes. An independent report audit confirmed all non-review
metrics unchanged, no released cases, retained L034/L240/L241 reviews, and source
provenance matching the v1 replay. Boundary verdicts and hash priorities remain
unchanged. Initially reviewed protected conflicts were absent from the cohorts;
preservation of their branches is checked by unit tests.

This is an exploratory policy designed after inspecting these cohorts. Exact
source connections do not establish full history, ancestry or a copying date.
The result supports preserving related uncertainty, but additional correspondence
evidence would be needed to distinguish unknown alternatives and reduce reviews.
