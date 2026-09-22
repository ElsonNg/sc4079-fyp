"""Coordinate reference-side scoring into localized verification evidence."""

from __future__ import annotations

from provtrail.pipeline.detection.config import RegionVerifierConfig
from provtrail.pipeline.models.boundary import VulnerableRegionPair
from provtrail.pipeline.models.evidence import (
    CandidateEvidenceReference, PairedEvidenceReference, ReferenceSideEvidence,
    RegionComparison, RegionVerificationEvidence,
)
from provtrail.pipeline.models.region import AstRegion
from provtrail.pipeline.detection.verification.structural import structural_score
from provtrail.pipeline.detection.verification.tokens import (
    token_score,
    api_anchor_score,
    role_tokens,
    signature_coverage,
)
from provtrail.pipeline.detection.verification.fallback import apply_containment


def _side_score(candidate: AstRegion, reference: AstRegion) -> ReferenceSideEvidence:
    """Collect the structural, token, and API measurements for one reference side."""
    structural = structural_score(candidate, reference)
    token = token_score(candidate, reference)
    return ReferenceSideEvidence(
        structural=structural,
        token=token,
        api_anchor=api_anchor_score(candidate, reference),
        score=min(structural, token),
    )


def verify_region_pair(
    candidate_region: AstRegion,
    pair: VulnerableRegionPair,
    retrieval_similarity: float,
    config: RegionVerifierConfig | None = None,
    candidate_function_name: str | None = None,
) -> RegionVerificationEvidence:
    config = config or RegionVerifierConfig()
    # Score the candidate against both versions of the same fix boundary.
    vulnerable = _side_score(candidate_region, pair.vulnerable_region)
    patched = _side_score(candidate_region, pair.patched_region)

    # Try containment when a whole-region comparison fails the structure or token gate.
    apply_containment(candidate_region, pair.vulnerable_region, vulnerable, config)
    apply_containment(candidate_region, pair.patched_region, patched, config)
    candidate_tokens = set(role_tokens(candidate_region))
    coverage = min(
        len(candidate_region.ast_shape), len(pair.vulnerable_region.ast_shape),
    ) / max(1, max(len(candidate_region.ast_shape), len(pair.vulnerable_region.ast_shape)))

    # Preserve both sides and their differences for the boundary classifier.
    return RegionVerificationEvidence(
        pair_id=pair.pair_id,
        retrieval_similarity=retrieval_similarity,
        candidate=CandidateEvidenceReference(
            region_id=candidate_region.region_id,
            span=candidate_region.span,
            granularity=candidate_region.granularity,
            function_name=candidate_function_name,
        ),
        reference=PairedEvidenceReference(
            vulnerable_region_id=pair.vulnerable_region.region_id,
            patched_region_id=pair.patched_region.region_id,
            granularity=pair.vulnerable_region.granularity,
        ),
        vulnerable=vulnerable,
        patched=patched,
        comparison=RegionComparison(
            correspondence_score=max(vulnerable.score, patched.score),
            margin=vulnerable.score - patched.score,
            ast_coverage=coverage,
            fix_signature_coverage=signature_coverage(pair.change.fix_signature_tokens, candidate_tokens),
            vulnerable_signature_coverage=signature_coverage(pair.change.vulnerable_signature_tokens, candidate_tokens),
            alignment_fallback_used=(
                vulnerable.containment_used or patched.containment_used
            ),
        ),
    )
