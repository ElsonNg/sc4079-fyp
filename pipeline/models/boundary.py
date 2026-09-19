"""Vulnerable/patched source pairs and verification decisions at a fix boundary."""

from typing import Literal

from pydantic import BaseModel, Field, computed_field

from shared.metadata import AdvisoryAlias, PackageAdvisory, SourceReference
from pipeline.models.records import (
    FlatRecordModel,
    VULNERABILITY_STATE_FIELDS,
    VULNERABLE_REGION_PAIR_FIELDS,
)
from pipeline.models.region import AstRegion, RegionChangeKind


VulnerabilityStatus = Literal["vulnerable", "patched", "uncertain"]


AbstentionReason = Literal[
    "NO_EVIDENCE",
    "S_FAILED",
    "T_FAILED",
    "E_NOT_RUN",
    "E_SIDE_WEAK",
    "E_MARGIN_AMBIGUOUS",
    "E_SIDE_AND_MARGIN_WEAK",
    "E_DIRECTION_UNRESOLVED",
    "CONTRASTIVE_CONFLICT",
    "IDENTITY_REJECTED",
    "CONTRADICTORY_EVIDENCE",
]


EditStrategy = Literal["not_run", "raw", "contrastive"]


SignatureEvidenceState = Literal["vulnerable_only", "fix_only", "both", "neither"]


FunctionIdentityState = Literal["match", "conflict", "unknown"]


class RegionChangeEvidence(BaseModel):
    # Shape of the patch, e.g. insertion, deletion or replacement.
    change_kind: RegionChangeKind = "unknown"
    # Number of changed lines describing the fix.
    diagnostic_line_count: int = 0
    # Removed tokens that characterize the vulnerable code.
    vulnerable_signature_tokens: list[str] = Field(default_factory=list)
    # Added tokens that characterize the fix.
    fix_signature_tokens: list[str] = Field(default_factory=list)
    # SHA-256 digest of the native vulnerable source.
    vulnerable_source_sha256: str
    # SHA-256 digest of the native patched source.
    patched_source_sha256: str


class VulnerableRegionPair(FlatRecordModel):
    record_groups = VULNERABLE_REGION_PAIR_FIELDS

    # Identifier for this vulnerable/patched region pair, e.g. "boundary-1:function".
    pair_id: str
    # Shared code-family identifier, when attribution is available.
    lineage_id: str | None = None
    # Identifier of the specific vulnerable-to-patched transition.
    fix_boundary_id: str = ""
    # All advisory aliases attached to this boundary, including shared CVEs.
    advisories: list[AdvisoryAlias] = Field(default_factory=list)
    # Source-backed AST region before the fix.
    vulnerable_region: AstRegion
    # Corresponding source-backed AST region after the fix.
    patched_region: AstRegion
    # Primary advisory and package metadata, e.g. GHSA, CVE and affected versions.
    advisory: PackageAdvisory
    # Upstream repository, fix commit and source location, e.g. "src/parse.js".
    origin: SourceReference
    # Fix-specific signatures, source digests and change classification.
    change: RegionChangeEvidence


class BoundaryIdentity(BaseModel):
    # Code family being assessed, e.g. a shared vulnerable function.
    lineage_id: str
    # Specific vulnerable-to-patched transition within that family.
    fix_boundary_id: str
    # Commit introducing the fix, e.g. "a1b2c3d".
    fix_commit_sha: str


class VerificationScores(BaseModel):
    # Selected vulnerable-side score; exact vulnerable matches score 1.0.
    vulnerable_score: float | None = None
    # Selected patched-side score; exact patched matches score 1.0.
    patched_score: float | None = None
    # Strongest side's combined structural/token correspondence.
    correspondence_score: float | None = None
    # Vulnerable minus patched score; positive values favour vulnerable.
    contrast_score: float | None = None
    # AST similarity to the vulnerable reference, e.g. 0.85.
    structural_vulnerable: float | None = None
    # AST similarity to the patched reference, e.g. 0.70.
    structural_patched: float | None = None
    # Token similarity to the vulnerable reference, e.g. 0.90.
    token_vulnerable: float | None = None
    # Token similarity to the patched reference, e.g. 0.75.
    token_patched: float | None = None


class BoundaryEditEvidence(BaseModel):
    # Edit comparison selected: not_run, raw or contrastive.
    strategy: EditStrategy = "not_run"
    # Selected edit similarity to removed vulnerable code.
    vulnerable: float | None = None
    # Selected edit similarity to added patched code.
    patched: float | None = None
    # Vulnerable minus patched edit similarity, e.g. 0.20.
    margin: float | None = None
    # Whether the vulnerable edit anchor identifies specific code.
    vulnerable_anchor_has_identity: bool | None = None
    # Whether the patched edit anchor identifies specific code.
    patched_anchor_has_identity: bool | None = None
    # Vulnerable edit similarity before common context is removed.
    raw_vulnerable: float | None = None
    # Patched edit similarity before common context is removed.
    raw_patched: float | None = None
    # Vulnerable edit similarity after common context is removed.
    contrastive_vulnerable: float | None = None
    # Patched edit similarity after common context is removed.
    contrastive_patched: float | None = None

    @computed_field
    @property
    def contrastive_used(self) -> bool:
        return self.strategy == "contrastive"


class VerificationGates(BaseModel):
    # Whether either reference side passes the structural threshold.
    structure_gate_passed: bool = False
    # Whether one observation passes both structural and token gates.
    token_gate_passed: bool = False
    # Whether surrounding block/function evidence supports correspondence.
    context_correspondence_passed: bool = False
    # Candidate/reference name relationship: match, conflict or unknown.
    function_identity_state: FunctionIdentityState = "unknown"
    # Whether the decisive side's edit anchor identifies specific code.
    edit_anchor_has_identity: bool | None = None
    # Whether contextual/name/anchor evidence permits this attribution.
    boundary_identity_gate_passed: bool = True

    @computed_field
    @property
    def boundary_rejected(self) -> bool:
        return not self.boundary_identity_gate_passed


class FallbackEvidence(BaseModel):
    # Whether failed initial gates made containment eligible for use.
    containment_attempted: bool = False
    # Whether containment supplied passing structural/token scores.
    containment_used: bool = False
    # Whether the optional late correspondence check ran.
    local_correspondence_attempted: bool = False
    # Whether that optional check resolved the uncertain verdict.
    local_correspondence_used: bool = False
    # Optional check's verdict, e.g. "patched"; None if not run.
    local_correspondence_status: VulnerabilityStatus | None = None
    # Decisive methods reported by the optional check.
    local_correspondence_methods: list[str] = Field(default_factory=list)
    # Explanation returned by the optional correspondence check.
    local_correspondence_reason: str | None = None
    # Uncertainty reason before the optional check, e.g. E_MARGIN_AMBIGUOUS.
    local_correspondence_prior_abstention_reason: AbstentionReason | None = None


class BoundarySupport(BaseModel):
    # Fraction of added fix signature tokens found, e.g. 0.80.
    fix_signature_coverage: float = 0.0
    # Fraction of removed vulnerable signature tokens found.
    vulnerable_signature_coverage: float = 0.0
    # Signatures present: vulnerable_only, fix_only, both or neither.
    signature_evidence_state: SignatureEvidenceState = "neither"
    # Number of independent observations after deduplication.
    independent_region_count: int = 0
    # Independent observations with a positive vulnerable-minus-patched score.
    vulnerable_support_count: int = 0
    # Independent observations with a negative vulnerable-minus-patched score.
    patched_support_count: int = 0
    # Largest side-support count divided by independent observations.
    side_consensus_ratio: float = 0.0
    # Readable evidence notes, e.g. "added fix signature present".
    fix_evidence: list[str] = Field(default_factory=list)
    # Conflicting evidence, e.g. both reference-side hashes match.
    contradictions: list[str] = Field(default_factory=list)


class VulnerabilityState(FlatRecordModel):
    record_groups = VULNERABILITY_STATE_FIELDS

    # Code family and fix being assessed, e.g. a lineage and its patch commit.
    boundary: BoundaryIdentity
    # Final boundary verdict: vulnerable, patched or uncertain.
    status: VulnerabilityStatus
    # Why no verdict was reached, e.g. E_MARGIN_AMBIGUOUS; otherwise None.
    abstention_reason: AbstentionReason | None = None
    # Reference-side similarity and contrast, e.g. structural_vulnerable=0.85.
    scores: VerificationScores = Field(default_factory=VerificationScores)
    # Patch-local edit evidence, e.g. strategy="raw" and margin=0.20.
    edit: BoundaryEditEvidence = Field(default_factory=BoundaryEditEvidence)
    # Checks controlling the verdict, e.g. token_gate_passed=True.
    gates: VerificationGates = Field(default_factory=VerificationGates)
    # Containment and optional correspondence activity, e.g. containment_used=True.
    fallbacks: FallbackEvidence = Field(default_factory=FallbackEvidence)
    # Supporting observations and conflicts, e.g. independent_region_count=2.
    support: BoundarySupport = Field(default_factory=BoundarySupport)
    # Advisory labels attached to this boundary, e.g. a GHSA and package name.
    advisories: list[AdvisoryAlias] = Field(default_factory=list)
    # Region-pair identifiers supporting the verdict, e.g. ["pair-1", "pair-2"].
    evidence_pair_ids: list[str] = Field(default_factory=list)
