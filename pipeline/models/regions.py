"""Typed contracts for AST-region retrieval and localized verification."""

from typing import Literal

from pydantic import BaseModel, Field

from corpus.models.github import CWE
from pipeline.models.hashing import HashMatch

RegionGranularity = Literal["changed", "block", "context", "function"]
RegionChangeKind = Literal["insertion", "deletion", "replacement", "movement", "mixed", "unknown"]
RegionStatus = Literal["flagged", "cleared", "manual_review"]
ProvenanceConfidence = Literal["high", "medium", "low", "ambiguous", "none"]


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
    vulnerable_source_sha256: str
    patched_source_sha256: str


class CandidateRegion(BaseModel):
    candidate_id: str | None = None
    function_name: str | None = None
    region: AstRegion


class RegionRetrievalMatch(BaseModel):
    pair_id: str
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


class RegionAggregate(BaseModel):
    pair_id: str
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
    provenance_confidence: ProvenanceConfidence = "none"
    fallback_used: bool = False


class RegionAdvisoryVerdict(BaseModel):
    """Verdict for one concrete advisory/fix/function corpus identity."""

    ghsa_id: str
    cve_id: str | None = None
    fix_commit_sha: str
    file_path: str
    function_name: str | None = None
    status: RegionStatus
    provenance_confidence: ProvenanceConfidence = "none"
    hash_match_types: list[str] = Field(default_factory=list)
    evidence_pair_ids: list[str] = Field(default_factory=list)
    message: str | None = None


class RegionDetectionResult(BaseModel):
    status: RegionStatus
    candidate_id: str | None = None
    provenance_confidence: ProvenanceConfidence = "none"
    hash_match_types: list[str] = Field(default_factory=list)
    hash_matches: list[HashMatch] = Field(default_factory=list)
    candidate_region_count: int
    retrieval_match_count: int
    aggregates: list[RegionAggregate] = Field(default_factory=list)
    evidence: list[RegionVerificationEvidence] = Field(default_factory=list)
    advisory_verdicts: list[RegionAdvisoryVerdict] = Field(default_factory=list)
    parser_supported: bool = True
    message: str | None = None
