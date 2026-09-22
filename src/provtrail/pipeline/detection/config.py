"""Detection settings and shared defaults, independent of implementation modules."""

from __future__ import annotations

from dataclasses import dataclass

DEFAULT_MODEL_ID = "qwen3-embedding-0.6b"
DEFAULT_REGION_TOP_K = 10
DEFAULT_REGION_THRESHOLD = 0.0
HIGH_LINEAGE_CONFIDENCE_MARGIN = 0.15


@dataclass(frozen=True)
class RegionVerifierConfig:
    """Thresholds and optional fallbacks for localized verification."""

    minimum_structure_score: float = 0.70
    minimum_token_score: float = 0.70
    minimum_edit_side_score: float = 0.90
    minimum_edit_margin: float = 0.10
    minimum_supporting_regions: int = 2
    minimum_consensus_ratio: float = 0.60
    contradiction_margin: float = 0.08
    signature_threshold: float = 0.65
    minimum_containment_coverage: float = 0.50
    include_containment_fallback: bool = True
    # None preserves uncapped evaluation behavior.
    max_containment_cells: int | None = None


@dataclass(frozen=True)
class RegionDetectorConfig:
    """Retrieval limits, verification settings and optional detection fallbacks."""

    model_id: str = DEFAULT_MODEL_ID
    retrieval_top_k: int = DEFAULT_REGION_TOP_K
    retrieval_threshold: float = DEFAULT_REGION_THRESHOLD
    max_candidate_regions: int = 96
    max_verification_candidates: int = 5
    max_verification_regions_per_pair: int = 3
    include_local_correspondence_fallback: bool = False
    # Oversized outer functions are skipped. Nested functions remain eligible.
    max_candidate_chars: int | None = None
    max_edit_candidate_chars: int | None = None
    verifier: RegionVerifierConfig = RegionVerifierConfig()
