"""Select reference pairs and their strongest region hits for verification."""

from provtrail.pipeline.controller.region_retrieval import aggregate_region_hits
from provtrail.pipeline.models.boundary import VulnerableRegionPair
from provtrail.pipeline.models.region_retrieval import RegionAggregate, RegionRetrievalMatch


def aggregate_retrieval_matches(
    matches: list[RegionRetrievalMatch],
    pairs: dict[str, VulnerableRegionPair],
    limit: int,
) -> list[RegionAggregate]:
    grouped = aggregate_region_hits(matches)
    aggregates: list[RegionAggregate] = []
    for pair_id, pair_matches in grouped:
        candidate_region_ids = sorted({match.candidate_region_id for match in pair_matches})
        granularities = sorted({match.candidate_granularity for match in pair_matches})
        aggregates.append(
            RegionAggregate(
                pair_id=pair_id,
                lineage_id=pairs[pair_id].lineage_id,
                fix_boundary_id=pairs[pair_id].fix_boundary_id,
                best_similarity=max(match.similarity for match in pair_matches),
                candidate_region_ids=candidate_region_ids,
                granularities=granularities,
                top_matches=sorted(pair_matches, key=lambda item: item.similarity, reverse=True)[:5],
            )
        )
    return aggregates[:limit]
