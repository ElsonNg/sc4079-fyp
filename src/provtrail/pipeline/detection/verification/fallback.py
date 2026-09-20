"""Containment fallback selection for localized verification."""

from __future__ import annotations

from provtrail.pipeline.detection.config import RegionVerifierConfig
from provtrail.pipeline.models.region import AstRegion
from provtrail.pipeline.models.evidence import ReferenceSideEvidence
from provtrail.pipeline.detection.verification.tokens import containment_components


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
