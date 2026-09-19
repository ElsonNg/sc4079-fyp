"""Compatibility imports for verification; remove after Phase 8 migration."""

import difflib

from pipeline.detection.config import RegionVerifierConfig
from pipeline.detection.verification.sequences import (
    sequence_similarity as _ratio,
    containment_similarity as _containment_score,
)
from pipeline.detection.verification.structural import (
    structural_score as _structural_score,
)
from pipeline.detection.verification.tokens import (
    _IDENTIFIER_RE,
    _API_ANCHOR_SEPARATOR_RE,
    _KEYWORDS,
    _jaccard,
    role_tokens as _role_tokens,
    token_score as _token_score,
    containment_components as _containment_components,
    _normalize_api_anchor,
    api_anchor_score as _api_anchor_score,
)
from pipeline.detection.verification.fallback import (
    local_line_score as _local_line_score,
    embedding_local_line_score as _embedding_local_line_score,
)
from pipeline.detection.verification.aggregation import (
    _GRANULARITY_WEIGHT,
    _overlap,
    effective_components as _effective_components,
    deduplicate_evidence,
)
from pipeline.detection.verification.classification import (
    _weighted_median,
    classify_boundary,
    classify_evidence,
)
from pipeline.detection.verification.verifier import (
    _side_score,
    verify_region_pair,
)
