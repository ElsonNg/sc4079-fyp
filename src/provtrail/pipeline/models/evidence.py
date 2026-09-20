"""Localized verification scores and package applicability evidence."""

from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, Field

from provtrail.pipeline.models.lineage import LineageConfidence
from provtrail.pipeline.models.records import FlatRecordModel, REGION_VERIFICATION_EVIDENCE_FIELDS
from provtrail.pipeline.models.region import RegionGranularity, SourceSpan


ApplicabilityStatus = Literal["confirmed", "conflicting", "unknown"]


class CandidateEvidenceReference(BaseModel):
    # Identifier of the candidate AST region, e.g. "candidate:1".
    region_id: str
    # Byte/line location in the candidate source, when available.
    span: SourceSpan | None = None
    # Candidate region size category, e.g. block or function.
    granularity: RegionGranularity = "function"
    # Candidate function name, e.g. "parse", when available.
    function_name: str | None = None


class PairedEvidenceReference(BaseModel):
    # Identifier of the vulnerable reference region.
    vulnerable_region_id: str
    # Identifier of the patched reference region.
    patched_region_id: str
    # Reference region size category, e.g. changed or function.
    granularity: RegionGranularity | None = None


class ReferenceSideEvidence(BaseModel):
    # AST similarity to this reference side, e.g. 0.90.
    structural: float
    # Token similarity to this reference side, e.g. 0.85.
    token: float
    # Similarity of calls/member access anchors. None when unavailable.
    api_anchor: float | None = None
    # Historical report field, always None after retiring local alignment.
    local_alignment: float | None = None
    # Selected side score after any successful containment fallback.
    score: float
    # AST similarity when matching a contained region.
    containment_structural: float | None = None
    # Token similarity when matching a contained region.
    containment_token: float | None = None
    # Smaller-to-larger region coverage, e.g. 0.50.
    containment_coverage: float | None = None
    # Whether containment supplied the selected passing scores.
    containment_used: bool = False
    # Whether failed initial gates made containment eligible.
    containment_attempted: bool = False


class RegionComparison(BaseModel):
    # Stronger selected reference-side score.
    correspondence_score: float | None = None
    # Vulnerable minus patched score. Positive favours vulnerable.
    margin: float
    # Candidate/vulnerable AST size coverage, e.g. 0.80.
    ast_coverage: float
    # Fraction of added fix tokens present in the candidate.
    fix_signature_coverage: float = 0.0
    # Fraction of removed vulnerable tokens present in the candidate.
    vulnerable_signature_coverage: float = 0.0
    # Confidence of shared origin: high, medium, low or none.
    lineage_confidence: LineageConfidence = "none"
    # Whether containment supplied either selected side score.
    alignment_fallback_used: bool = False


class RegionVerificationEvidence(FlatRecordModel):
    record_groups = REGION_VERIFICATION_EVIDENCE_FIELDS

    # Identifier for this vulnerable/patched region pair, e.g. "boundary-1:function".
    pair_id: str
    # Embedding similarity that shortlisted this pair, e.g. 0.95.
    retrieval_similarity: float
    # Candidate region location and identity, e.g. span and function name.
    candidate: CandidateEvidenceReference
    # Identifiers of the vulnerable and patched reference regions.
    reference: PairedEvidenceReference
    # Measurements against vulnerable code, e.g. structural=0.90.
    vulnerable: ReferenceSideEvidence
    # Measurements against patched code, e.g. token=0.75.
    patched: ReferenceSideEvidence
    # Combined comparison, signature coverage and lineage confidence.
    comparison: RegionComparison


class ApplicabilityEvidence(BaseModel):
    kind: str
    source: str
    package: str | None = None
    version: str | None = None
    detail: str | None = None


class PackageApplicability(BaseModel):
    lineage_id: str
    package: str
    ecosystem: str = "npm"
    status: ApplicabilityStatus = "unknown"
    evidence: list[ApplicabilityEvidence] = Field(default_factory=list)


@dataclass(frozen=True)
class EditDistanceEvidence:
    vulnerable: float
    patched: float
    vulnerable_anchor_has_identity: bool | None = None
    patched_anchor_has_identity: bool | None = None
    raw_vulnerable: float | None = None
    raw_patched: float | None = None
    raw_vulnerable_anchor_has_identity: bool | None = None
    raw_patched_anchor_has_identity: bool | None = None
    contrastive_vulnerable: float | None = None
    contrastive_patched: float | None = None
    contrastive_vulnerable_anchor_has_identity: bool | None = None
    contrastive_patched_anchor_has_identity: bool | None = None
    contrastive_used: bool = False

    @property
    def margin(self) -> float:
        return self.vulnerable - self.patched
