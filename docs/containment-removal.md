# Verification after containment removal

The detector compares each candidate region with the vulnerable and patched
reference regions using ordinary structural and role-normalized token similarity.
Each side's score is the minimum of those two measurements. Boundary
classification uses these measurements directly; additional candidate code can
lower correspondence instead of triggering a second substring comparison.

The containment implementation, configuration switches, coverage threshold,
computation limit and output diagnostics have been removed. The region-level
`fallback_used` diagnostic has also been removed because it described this
feature. Optional local correspondence remains a separate detector option.
Hash matching, region extraction, retrieval limits, edit verification and their
existing defaults are unchanged.

## Compatibility

Older flat or grouped evidence records still load. Retired containment fields
are ignored and are omitted when records are serialized again. Loading a saved
record does not rerun its verdict or update its historical scores.

Configurations containing `include_containment_fallback`,
`minimum_containment_coverage` or `max_containment_cells` must remove those keys.
There is no switch to restore containment.

## Experimental records

Saved manifests, raw results and historical summaries retain their original
settings. Existing source-hash checks prevent historical frozen runs from being
resumed against the modified detector. Reproduce those runs using their original
source revision and environment.

Before the next region-type or component study, create a new source/configuration
manifest and a separate output directory. Historical containment-enabled
parameter and component results must not be presented as measurements of this
implementation. The historical `no_containment` arm remains evidence for the
previously evaluated operating point, not a fresh timing measurement after this
removal. Historical local experiment helpers that patch the removed functions
also require their original source revision; they are not current detector APIs.
