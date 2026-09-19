"""Compatibility imports for region models; remove after Phase 8 import migration."""

from typing import Literal

from pydantic import BaseModel, Field

from corpus.models.github import CWE
from pipeline.models.hashing import HashMatch
from pipeline.models.provenance import AdvisoryAlias
from pipeline.models.region import (
    RegionGranularity,
    RegionChangeKind,
    SourceSpan,
    AstRegion,
    CandidateRegion,
)
from pipeline.models.boundary import (
    VulnerabilityStatus,
    AbstentionReason,
    EditStrategy,
    SignatureEvidenceState,
    FunctionIdentityState,
    VulnerableRegionPair,
    VulnerabilityState,
)
from pipeline.models.region_retrieval import (
    RegionRetrievalMatch,
    RegionAggregate,
)
from pipeline.models.evidence import (
    ApplicabilityStatus,
    RegionVerificationEvidence,
    ApplicabilityEvidence,
    PackageApplicability,
)
from pipeline.models.lineage import (
    LineageConfidence,
    LineageAttribution,
)
from pipeline.models.result import (
    FindingPriority,
    RegionDetectionResult,
)

__all__ = [
    "AdvisoryAlias",
    "BaseModel",
    "CWE",
    "Field",
    "HashMatch",
    "Literal",
    "AbstentionReason",
    "ApplicabilityEvidence",
    "ApplicabilityStatus",
    "AstRegion",
    "CandidateRegion",
    "EditStrategy",
    "FindingPriority",
    "FunctionIdentityState",
    "LineageAttribution",
    "LineageConfidence",
    "PackageApplicability",
    "RegionAggregate",
    "RegionChangeKind",
    "RegionDetectionResult",
    "RegionGranularity",
    "RegionRetrievalMatch",
    "RegionVerificationEvidence",
    "SignatureEvidenceState",
    "SourceSpan",
    "VulnerabilityState",
    "VulnerabilityStatus",
    "VulnerableRegionPair",
]
