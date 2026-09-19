"""Coordinate reference-side scoring into localized verification evidence."""

from __future__ import annotations

from pipeline.detection.config import RegionVerifierConfig
from pipeline.models.boundary import VulnerableRegionPair
from pipeline.models.evidence import (
    CandidateEvidenceReference, PairedEvidenceReference, ReferenceSideEvidence,
    RegionComparison, RegionVerificationEvidence,
)
from pipeline.models.region import AstRegion
from pipeline.detection.verification.structural import structural_score
from pipeline.detection.verification.tokens import (
    token_score,
    api_anchor_score,
    role_tokens,
    signature_coverage,
)
from pipeline.detection.verification.fallback import (
    apply_containment, local_line_score, embedding_local_line_score,
)


def _side_score(
    candidate: AstRegion,
    reference: AstRegion,
    config: RegionVerifierConfig,
    model_id: str | None,
    use_embedding_alignment: bool,
    language: str,
) -> tuple[float, float, float, float | None, float | None, bool]:
    structural = structural_score(candidate, reference)
    token = token_score(candidate, reference)
    api_anchor = api_anchor_score(candidate, reference)
    local: float | None = None
    fallback = False
    if config.include_local_alignment:
        local = local_line_score(candidate, reference)
        if structural < config.local_alignment_trigger and use_embedding_alignment and model_id:
            try:
                local = embedding_local_line_score(candidate, reference, model_id)
                fallback = True
            except Exception:
                # Keep the lexical score while recording that embedding alignment was attempted.
                fallback = True
        score = min(structural, token, local)
    else:
        # A compatibility summary of the staged gates, not an averaged score.
        score = min(structural, token)
    return score, structural, token, api_anchor, local, fallback


def score_reference_side(
    candidate: AstRegion,
    reference: AstRegion,
    config: RegionVerifierConfig,
    model_id: str | None,
    use_embedding_alignment: bool,
    language: str,
) -> tuple[ReferenceSideEvidence, bool]:
    score, structural, token, api_anchor, local, fallback = _side_score(
        candidate, reference, config, model_id, use_embedding_alignment, language
    )
    return ReferenceSideEvidence(
        structural=structural, token=token, api_anchor=api_anchor,
        local_alignment=local, score=score,
    ), fallback


def verify_region_pair(
    candidate_region: AstRegion,
    pair: VulnerableRegionPair,
    retrieval_similarity: float,
    config: RegionVerifierConfig | None = None,
    model_id: str | None = None,
    use_embedding_alignment: bool = False,
    language: str = "javascript",
    candidate_function_name: str | None = None,
) -> RegionVerificationEvidence:
    config = config or RegionVerifierConfig()
    # Score the candidate against both versions of the same fix boundary.
    vulnerable, vulnerable_alignment = score_reference_side(
        candidate_region, pair.vulnerable_region, config,
        model_id, use_embedding_alignment, language,
    )
    patched, patched_alignment = score_reference_side(
        candidate_region, pair.patched_region, config,
        model_id, use_embedding_alignment, language,
    )
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
                vulnerable_alignment or patched_alignment
                or vulnerable.containment_used or patched.containment_used
            ),
        ),
    )
