"""Typed contracts for AST-region retrieval and localized verification."""

from typing import Literal

from pydantic import BaseModel, Field

from corpus.models.github import CWE
from pipeline.models.hashing import HashMatch
from pipeline.models.provenance import AdvisoryAlias

RegionGranularity = Literal["changed", "block", "context", "function"]
RegionChangeKind = Literal["insertion", "deletion", "replacement", "movement", "mixed", "unknown"]
LineageConfidence = Literal["high", "medium", "low", "none"]
VulnerabilityStatus = Literal["vulnerable", "patched", "uncertain"]
ApplicabilityStatus = Literal["confirmed", "conflicting", "unknown"]
FindingPriority = Literal[
    "automatic_vulnerability", "manual_review", "informational_lineage", "none"
]


class SourceSpan(BaseModel):
    start_byte: int
    end_byte: int
    start_line: int
    end_line: int


class AstRegion(BaseModel):
    """A source-backed AST slice with enough context for retrieval and evidence."""

    region_id: str
    source: str
    span: SourceSpan
    granularity: RegionGranularity
    node_type: str
    ast_path: list[str] = Field(default_factory=list)
    ast_shape: list[str] = Field(default_factory=list)
    normalized_tokens: list[str] = Field(default_factory=list)
    calls: list[str] = Field(default_factory=list)
    member_accesses: list[str] = Field(default_factory=list)
    identifiers: list[str] = Field(default_factory=list)
    literals: list[str] = Field(default_factory=list)
    embedding_text: str


class VulnerableRegionPair(BaseModel):
    pair_id: str
    lineage_id: str | None = None
    fix_boundary_id: str = ""
    advisories: list[AdvisoryAlias] = Field(default_factory=list)
    ghsa_id: str
    cve_id: str | None = None
    advisory_title: str = ""
    advisory_description: str = ""
    advisory_url: str = ""
    advisory_references: list[str] = Field(default_factory=list)
    cwes: list[CWE] = Field(default_factory=list)
    severity: str = "unknown"
    repo: str
    fix_commit_sha: str
    file_path: str
    function_name: str | None = None
    package_name: str
    ecosystem: str = "npm"
    osv_id: str | None = None
    affected_versions: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    vulnerable_region: AstRegion
    patched_region: AstRegion
    change_kind: RegionChangeKind = "unknown"
    diagnostic_line_count: int = 0
    vulnerable_signature_tokens: list[str] = Field(default_factory=list)
    fix_signature_tokens: list[str] = Field(default_factory=list)
    vulnerable_source_sha256: str
    patched_source_sha256: str
    source_language: str = "javascript"
    representation: Literal["native", "type_erased"] = "native"


class CandidateRegion(BaseModel):
    candidate_id: str | None = None
    function_name: str | None = None
    region: AstRegion


class RegionRetrievalMatch(BaseModel):
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
    ghsa_id: str
    cve_id: str | None = None
    osv_id: str | None = None
    advisory_title: str = ""
    advisory_description: str = ""
    advisory_url: str = ""
    advisory_references: list[str] = Field(default_factory=list)
    cwes: list[CWE] = Field(default_factory=list)
    severity: str = "unknown"
    package_name: str | None = None
    ecosystem: str | None = None
    affected_versions: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    fix_commit_sha: str
    file_path: str
    function_name: str | None = None
    source_language: str = "javascript"
    representation: Literal["native", "type_erased"] = "native"


class RegionAggregate(BaseModel):
    pair_id: str
    lineage_id: str | None = None
    fix_boundary_id: str | None = None
    best_similarity: float
    support_count: int
    candidate_region_ids: list[str] = Field(default_factory=list)
    granularities: list[RegionGranularity] = Field(default_factory=list)
    top_matches: list[RegionRetrievalMatch] = Field(default_factory=list)


class RegionVerificationEvidence(BaseModel):
    pair_id: str
    candidate_region_id: str
    vulnerable_region_id: str
    patched_region_id: str
    retrieval_similarity: float
    structural_vulnerable: float
    structural_patched: float
    token_vulnerable: float
    token_patched: float
    semantic_vulnerable: float | None = None
    semantic_patched: float | None = None
    local_alignment_vulnerable: float | None = None
    local_alignment_patched: float | None = None
    vulnerable_score: float
    patched_score: float
    vulnerable_minus_patched: float
    ast_coverage: float
    candidate_span: SourceSpan | None = None
    candidate_granularity: RegionGranularity = "function"
    fix_signature_coverage: float = 0.0
    vulnerable_signature_coverage: float = 0.0
    lineage_confidence: LineageConfidence = "none"
    fallback_used: bool = False


class LineageAttribution(BaseModel):
    lineage_id: str
    confidence: LineageConfidence
    score: float
    repo: str
    file_path: str
    reference_function: str | None = None
    associated_advisories: list[AdvisoryAlias] = Field(default_factory=list)
    evidence_pair_ids: list[str] = Field(default_factory=list)


class VulnerabilityState(BaseModel):
    lineage_id: str
    fix_boundary_id: str
    fix_commit_sha: str
    status: VulnerabilityStatus
    vulnerable_score: float | None = None
    patched_score: float | None = None
    contrast_score: float | None = None
    fix_signature_coverage: float = 0.0
    vulnerable_signature_coverage: float = 0.0
    fix_evidence: list[str] = Field(default_factory=list)
    contradictions: list[str] = Field(default_factory=list)
    advisories: list[AdvisoryAlias] = Field(default_factory=list)
    evidence_pair_ids: list[str] = Field(default_factory=list)


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
