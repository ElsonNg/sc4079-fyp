"""Ranked region matches and aggregated retrieval support."""

from typing import Literal

from pydantic import BaseModel, Field, computed_field

from provtrail.shared.metadata import AdvisoryAlias, SourceLocation
from provtrail.shared.records import MetadataRecord
from provtrail.pipeline.models.region import RegionGranularity


class RegionRetrievalMatch(MetadataRecord):
    advisory: AdvisoryAlias
    origin: SourceLocation

    pair_id: str
    lineage_id: str | None = None
    fix_boundary_id: str = ""
    reference_side: Literal["vulnerable", "patched"] = "vulnerable"
    advisories: list[AdvisoryAlias] = Field(default_factory=list)
    similarity: float
    rank: int
    candidate_region_id: str
    candidate_granularity: RegionGranularity
    corpus_granularity: RegionGranularity


class RegionAggregate(BaseModel):
    pair_id: str
    lineage_id: str | None = None
    fix_boundary_id: str | None = None
    best_similarity: float
    candidate_region_ids: list[str] = Field(default_factory=list)
    granularities: list[RegionGranularity] = Field(default_factory=list)
    top_matches: list[RegionRetrievalMatch] = Field(default_factory=list)

    @computed_field
    @property
    def support_count(self) -> int:
        return len(self.candidate_region_ids)
