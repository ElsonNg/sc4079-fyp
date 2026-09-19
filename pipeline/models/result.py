"""Final detection results combining retrieval, lineage and verification evidence."""

from typing import Literal

from pydantic import BaseModel, Field, ValidationInfo, field_serializer, field_validator

from pipeline.models.boundary import VulnerabilityState
from pipeline.models.evidence import PackageApplicability, RegionVerificationEvidence
from pipeline.models.hashing import HashMatch
from pipeline.models.lineage import LineageAttribution
from pipeline.models.region_retrieval import RegionAggregate


FindingPriority = Literal[
    "automatic_vulnerability", "manual_review", "informational_lineage", "none"
]


class RegionDetectionResult(BaseModel):
    priority: FindingPriority = "none"
    candidate_id: str | None = None
    hash_match_types: list[str] = Field(default_factory=list)
    hash_matches: list[HashMatch] = Field(default_factory=list)
    candidate_region_count: int
    retrieval_match_count: int
    aggregates: list[RegionAggregate] = Field(default_factory=list)
    evidence: list[RegionVerificationEvidence] = Field(default_factory=list)
    lineages: list[LineageAttribution] = Field(default_factory=list)
    vulnerability_states: list[VulnerabilityState] = Field(default_factory=list)
    package_applicabilities: list[PackageApplicability] = Field(default_factory=list)
    parser_supported: bool = True
    message: str | None = None

    @field_validator("hash_matches", "evidence", "vulnerability_states", mode="before")
    @classmethod
    def read_evidence_records(cls, values, info: ValidationInfo):
        if not isinstance(values, (list, tuple)):
            return values
        model = {
            "hash_matches": HashMatch,
            "evidence": RegionVerificationEvidence,
            "vulnerability_states": VulnerabilityState,
        }[info.field_name]
        return [
            model.from_record(value)
            if isinstance(value, dict) and not any(group in value for group in model.record_groups)
            else value
            for value in values
        ]

    @field_serializer("hash_matches", "evidence", "vulnerability_states")
    def write_evidence_records(self, values):
        return [value.to_record() for value in values]
