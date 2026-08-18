"""Localized AST/token verification for retrieved vulnerable regions."""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass

from pipeline.controller.parsing import normalize_source
from pipeline.models.regions import (
    AstRegion,
    ProvenanceConfidence,
    RegionAggregate,
    RegionDetectionResult,
    RegionVerificationEvidence,
    VulnerableRegionPair,
)

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")
_KEYWORDS = {
    "if", "else", "for", "while", "do", "switch", "case", "return", "throw", "try",
    "catch", "finally", "const", "let", "var", "new", "function", "class", "await",
    "async", "true", "false", "null", "undefined", "this", "typeof", "instanceof",
}


@dataclass(frozen=True)
class RegionVerifierConfig:
    """Initial provisional gates; calibration replaces these on held-out advisories.

    Local alignment remains available as an explicit later ablation, but is
    disabled for the active verifier while the simpler three-signal score is
    being evaluated.
    """

    minimum_vulnerable_score: float = 0.75
    minimum_margin: float = 0.08
    local_alignment_trigger: float = 0.72
    include_local_alignment: bool = False


def _ratio(left: list[str], right: list[str]) -> float:
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return difflib.SequenceMatcher(a=left, b=right, autojunk=False).ratio()


def _jaccard(left: list[str], right: list[str]) -> float | None:
    a, b = set(left), set(right)
    if not a and not b:
        return None
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _role_tokens(region: AstRegion) -> list[str]:
    tokens: list[str] = []
    literal_values = set(region.literals)
    for token in region.normalized_tokens:
        if token in literal_values:
            tokens.append("LIT")
        elif _IDENTIFIER_RE.match(token) and token not in _KEYWORDS:
            tokens.append("ID")
        else:
            tokens.append(token)
    return tokens


def _structural_score(candidate: AstRegion, reference: AstRegion) -> float:
    shape = _ratio(candidate.ast_shape, reference.ast_shape)
    path = _ratio(candidate.ast_path, reference.ast_path)
    return 0.50 * shape + 0.50 * path


def _token_score(candidate: AstRegion, reference: AstRegion) -> float:
    role_score = _ratio(_role_tokens(candidate), _role_tokens(reference))
    return role_score


def _semantic_score(candidate: AstRegion, reference: AstRegion) -> float | None:
    calls = _jaccard(candidate.calls, reference.calls)
    members = _jaccard(candidate.member_accesses, reference.member_accesses)
    available = [score for score in (calls, members) if score is not None]
    return sum(available) / len(available) if available else None


def _local_line_score(candidate: AstRegion, reference: AstRegion) -> float:
    return _ratio(normalize_source(candidate.source), normalize_source(reference.source))


def _embedding_local_line_score(candidate: AstRegion, reference: AstRegion, model_id: str) -> float:
    """Use the existing line aligner only for a difficult, already-localized pair."""
    from pipeline.controller.alignment import align

    alignment = align(
        normalize_source(candidate.source),
        normalize_source(reference.source),
        model_id=model_id,
    )
    return max(0.0, min(1.0, (alignment.normalized_score + 1.0) / 2.0))


def _side_score(
    candidate: AstRegion,
    reference: AstRegion,
    config: RegionVerifierConfig,
    model_id: str | None,
    use_embedding_alignment: bool,
) -> tuple[float, float, float, float | None, float | None, bool]:
    structural = _structural_score(candidate, reference)
    token = _token_score(candidate, reference)
    semantic = _semantic_score(candidate, reference)
    local: float | None = None
    fallback = False
    if config.include_local_alignment:
        local = _local_line_score(candidate, reference)
        if structural < config.local_alignment_trigger and use_embedding_alignment and model_id:
            try:
                local = _embedding_local_line_score(candidate, reference, model_id)
                fallback = True
            except Exception:
                fallback = True
        weighted = [(structural, 0.40), (token, 0.30), (local, 0.10)]
        if semantic is not None:
            weighted.append((semantic, 0.20))
        score = sum(value * weight for value, weight in weighted) / sum(weight for _, weight in weighted)
    else:
        available = [structural, token]
        if semantic is not None:
            available.append(semantic)
        score = sum(available) / len(available)
    return score, structural, token, semantic, local, fallback


def verify_region_pair(
    candidate_region: AstRegion,
    pair: VulnerableRegionPair,
    retrieval_similarity: float,
    config: RegionVerifierConfig | None = None,
    model_id: str | None = None,
    use_embedding_alignment: bool = False,
) -> RegionVerificationEvidence:
    config = config or RegionVerifierConfig()
    vuln_score, vuln_struct, vuln_token, vuln_semantic, vuln_local, vuln_fallback = _side_score(
        candidate_region,
        pair.vulnerable_region,
        config,
        model_id,
        use_embedding_alignment,
    )
    patch_score, patch_struct, patch_token, patch_semantic, patch_local, patch_fallback = _side_score(
        candidate_region,
        pair.patched_region,
        config,
        model_id,
        use_embedding_alignment,
    )
    margin = vuln_score - patch_score
    coverage = min(
        len(candidate_region.ast_shape),
        len(pair.vulnerable_region.ast_shape),
    ) / max(1, max(len(candidate_region.ast_shape), len(pair.vulnerable_region.ast_shape)))
    return RegionVerificationEvidence(
        pair_id=pair.pair_id,
        candidate_region_id=candidate_region.region_id,
        vulnerable_region_id=pair.vulnerable_region.region_id,
        patched_region_id=pair.patched_region.region_id,
        retrieval_similarity=retrieval_similarity,
        structural_vulnerable=vuln_struct,
        structural_patched=patch_struct,
        token_vulnerable=vuln_token,
        token_patched=patch_token,
        semantic_vulnerable=vuln_semantic,
        semantic_patched=patch_semantic,
        local_alignment_vulnerable=vuln_local,
        local_alignment_patched=patch_local,
        vulnerable_score=vuln_score,
        patched_score=patch_score,
        vulnerable_minus_patched=margin,
        ast_coverage=coverage,
        fallback_used=vuln_fallback or patch_fallback,
    )


def classify_evidence(
    evidence: list[RegionVerificationEvidence],
    aggregates: list[RegionAggregate],
    config: RegionVerifierConfig | None = None,
) -> tuple[str, ProvenanceConfidence]:
    config = config or RegionVerifierConfig()
    if not evidence:
        return "cleared", "none"
    passing = [
        item for item in evidence
        if item.vulnerable_score >= config.minimum_vulnerable_score
        and item.vulnerable_minus_patched >= config.minimum_margin
    ]
    if passing:
        best = max(passing, key=lambda item: (item.vulnerable_minus_patched, item.vulnerable_score))
        status = "flagged"
    else:
        best = max(evidence, key=lambda item: (item.vulnerable_minus_patched, item.vulnerable_score))
    if not passing and best.vulnerable_minus_patched <= -config.minimum_margin:
        status = "cleared"
    elif not passing:
        status = "manual_review"

    aggregate = next((item for item in aggregates if item.pair_id == best.pair_id), None)
    support = aggregate.support_count if aggregate else 1
    granularity_count = len(aggregate.granularities) if aggregate else 1
    if status != "flagged":
        confidence: ProvenanceConfidence = "ambiguous" if evidence else "none"
    elif support >= 3 and granularity_count >= 2 and best.vulnerable_minus_patched >= 0.15:
        confidence = "high"
    elif support >= 2 or granularity_count >= 2:
        confidence = "medium"
    else:
        confidence = "low"
    return status, confidence
