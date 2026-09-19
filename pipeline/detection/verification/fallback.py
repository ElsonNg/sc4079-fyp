"""Optional line alignment and containment fallback selection."""

from __future__ import annotations

from pipeline.controller.parsing import normalize_source
from pipeline.detection.config import RegionVerifierConfig
from pipeline.models.region import AstRegion
from pipeline.models.evidence import ReferenceSideEvidence
from pipeline.detection.verification.sequences import sequence_similarity
from pipeline.detection.verification.tokens import containment_components


def local_line_score(candidate: AstRegion, reference: AstRegion) -> float:
    return sequence_similarity(normalize_source(candidate.source), normalize_source(reference.source))


def embedding_local_line_score(candidate: AstRegion, reference: AstRegion, model_id: str) -> float:
    """Use the existing line aligner only for a difficult, already-localized pair."""
    from pipeline.controller.alignment import align

    alignment = align(
        normalize_source(candidate.source),
        normalize_source(reference.source),
        model_id=model_id,
    )
    return max(0.0, min(1.0, (alignment.normalized_score + 1.0) / 2.0))


def apply_containment(
    candidate: AstRegion,
    reference: AstRegion,
    evidence: ReferenceSideEvidence,
    config: RegionVerifierConfig,
) -> None:
    # Measurements remain available even when fallback selection is disabled.
    structural, token, coverage = containment_components(
        candidate, reference, config.max_containment_cells
    )
    attempted = config.include_containment_fallback and not (
        evidence.structural >= config.minimum_structure_score
        and evidence.token >= config.minimum_token_score
    )
    used = (
        attempted
        and coverage >= config.minimum_containment_coverage
        and structural >= config.minimum_structure_score
        and token >= config.minimum_token_score
    )
    evidence.containment_structural = structural
    evidence.containment_token = token
    evidence.containment_coverage = coverage
    evidence.containment_attempted = attempted
    evidence.containment_used = used
    if used:
        evidence.score = min(structural, token)
