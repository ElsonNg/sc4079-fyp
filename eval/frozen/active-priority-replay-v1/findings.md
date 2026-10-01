# Priority replay findings

## Decision

Do not adopt `patch_specific_uncertainty_v1` as the production priority rule.
It reduces review demand but releases vulnerable-labelled cases from review.
The production detector and historical results remain unchanged.

## Block + function

| Scope | Reviews before | Reviews after | Patched cases released | Vulnerable cases released |
|---|---:|---:|---:|---:|
| Tier 2 tuning | 31 | 18 | 13 | 0 |
| Tier 2 evaluation | 73 | 44 | 28 | 1 |
| Tier 2 all | 104 | 62 | 41 | 1 |

Correct-origin automatic detection remains 185/210 and patched false alerts
remain 12/212 on evaluation. Those unchanged counts are guaranteed by the
policy's construction; they do not establish that released reviews are safe.
The 28 released patched evaluation cases include the 15 newly reviewed cases
identified when context was removed.

## The counterexample: L034

L034 is a vulnerable-labelled Nuxt snippet in the evaluation split. Its expected
boundary is GHSA-7c4v-fwgw-9rf7, commit
`00f71bb6517abff67257c8ea1fcdc777b938b68d`, in
`packages/nitro-server/src/index.ts`.

In the block/function checkpoint:

- Another boundary in the same code lineage, GHSA-rq7w-g337-39qq, is verified
  patched (patch-side edit score 0.95).
- The expected boundary remains uncertain with `E_SIDE_WEAK`, despite high
  lineage confidence and structural/token correspondence. Its vulnerable-side
  edit score is 0.7857; its patched-side score is 0.40.
- The experimental policy removes review because the expected boundary fails
  the 0.90 identifying-anchor criterion. Its existing uncertain verdict is kept,
  but overall priority becomes informational.

This is a concrete reason to preserve review: code can include an earlier fix
while remaining vulnerable relative to another fix. A patch for one boundary
does not justify suppressing another boundary in that code family.
L034 is released in all seven region settings. These are repeated outcomes for
one case, not seven independent vulnerable snippets.

## Other releases

The no-function setting additionally releases tuning cases L240 and L241,
vulnerable-labelled LiquidJS `sort_natural` snippets. Their expected boundary
fails structural verification, while another `sample` boundary is reported
patched. Both cases lose review under the experiment. The tuning/evaluation
counts are available separately in `tables.md`.

## Limitations and next direction

No initially reviewed contradiction/contrastive-conflict/hash-ambiguity cases
were present in these cohorts (the tables show 0/0). Preservation of these
branches is covered by unit tests, not demonstrated by cohort positives.
Original hash priorities and boundary evidence were preserved across the replay.

A subsequent policy should distinguish alternative fixes within the same code
lineage from generic similarities to different functions. It must preserve
L034-style multi-fix uncertainty and handle cross-function attribution errors
such as `sort_natural` versus `sample`. Do not special-case these candidate IDs
or use expected-origin labels in the runtime rule. Independent controls with
multiple fixes and mixed vulnerable/patched findings are needed before adoption.
