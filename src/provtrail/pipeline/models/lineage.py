"""Attribution of candidate code to an advisory-associated source lineage."""

from typing import Literal

from pydantic import BaseModel, Field

from provtrail.shared.metadata import AdvisoryAlias


LineageConfidence = Literal["high", "medium", "low", "none"]


class LineageAttribution(BaseModel):
    lineage_id: str
    confidence: LineageConfidence
    score: float
    repo: str
    file_path: str
    reference_function: str | None = None
    associated_advisories: list[AdvisoryAlias] = Field(default_factory=list)
    evidence_pair_ids: list[str] = Field(default_factory=list)
