"""Compatibility imports for edit scoring; remove after Phase 8 migration."""

from pipeline.models.evidence import EditDistanceEvidence
from pipeline.detection.verification.edit_distance import (
    _KEYWORDS,
    _LEX,
    _IDENTIFIER,
    role_tokens,
    anchor_has_identity,
    fuzzy_substring_similarity,
    _line_value,
    _coverage,
    _best_anchor_has_identity,
    _DELTA_OPERATORS,
    _DELTA_KEYWORDS,
    _is_distinctive_token,
    _contrastive_anchors,
    score_edit_distance,
)
