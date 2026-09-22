"""AST shape and ancestry similarity."""

from __future__ import annotations

from provtrail.pipeline.models.region import AstRegion
from provtrail.pipeline.detection.verification.sequences import sequence_similarity


def structural_score(candidate: AstRegion, reference: AstRegion) -> float:
    shape = sequence_similarity(candidate.ast_shape, reference.ast_shape)
    path = sequence_similarity(candidate.ast_path, reference.ast_path)
    return 0.50 * shape + 0.50 * path
