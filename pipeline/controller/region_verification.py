"""Localized AST/token verification for retrieved vulnerable regions."""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass

from pipeline.controller.parsing import normalize_source
from pipeline.models.regions import (
    AstRegion,
    LineageConfidence,
    RegionAggregate,
    RegionVerificationEvidence,
    VulnerabilityState,
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
    minimum_supporting_regions: int = 2
    minimum_consensus_ratio: float = 0.60
    contradiction_margin: float = 0.08
    patched_margin: float = 0.08
    signature_threshold: float = 0.65
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
    candidate_tokens = set(_role_tokens(candidate_region))

    def signature_coverage(values: list[str]) -> float:
        signature = {
            "ID" if _IDENTIFIER_RE.match(token) and token not in _KEYWORDS else token
            for token in values
            if token.strip()
        }
        return len(signature & candidate_tokens) / len(signature) if signature else 0.0

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
        candidate_span=candidate_region.span,
        candidate_granularity=candidate_region.granularity,
        fix_signature_coverage=signature_coverage(pair.fix_signature_tokens),
        vulnerable_signature_coverage=signature_coverage(pair.vulnerable_signature_tokens),
        fallback_used=vuln_fallback or patch_fallback,
    )


_GRANULARITY_WEIGHT = {"changed": 4.0, "block": 3.0, "context": 2.0, "function": 1.0}


def _overlap(left: RegionVerificationEvidence, right: RegionVerificationEvidence) -> bool:
    if left.candidate_span is None or right.candidate_span is None:
        return left.candidate_region_id == right.candidate_region_id
    return (
        left.candidate_span.start_byte < right.candidate_span.end_byte
        and right.candidate_span.start_byte < left.candidate_span.end_byte
    )


def deduplicate_evidence(
    evidence: list[RegionVerificationEvidence],
) -> list[RegionVerificationEvidence]:
    """Collapse overlapping AST windows so nesting cannot manufacture support."""

    ordered = sorted(
        evidence,
        key=lambda item: (
            -_GRANULARITY_WEIGHT[item.candidate_granularity],
            -item.ast_coverage,
            -abs(item.vulnerable_minus_patched),
            item.candidate_region_id,
        ),
    )
    selected: list[RegionVerificationEvidence] = []
    for item in ordered:
        if not any(_overlap(item, existing) for existing in selected):
            selected.append(item)
    return selected


def _weighted_median(values: list[tuple[float, float]]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    halfway = sum(weight for _, weight in ordered) / 2.0
    running = 0.0
    for value, weight in ordered:
        running += weight
        if running >= halfway:
            return value
    return ordered[-1][0]


def classify_boundary(
    evidence: list[RegionVerificationEvidence],
    pair: VulnerableRegionPair,
    config: RegionVerifierConfig | None = None,
) -> VulnerabilityState:
    """Classify one fix boundary from independent, changed-region-led evidence."""

    config = config or RegionVerifierConfig()
    independent = deduplicate_evidence(evidence)
    if not independent:
        return VulnerabilityState(
            lineage_id=pair.lineage_id or "",
            fix_boundary_id=pair.fix_boundary_id,
            fix_commit_sha=pair.fix_commit_sha,
            status="uncertain",
            advisories=pair.advisories,
        )
    weighted = [
        (
            item.vulnerable_minus_patched,
            _GRANULARITY_WEIGHT[item.candidate_granularity] * max(item.ast_coverage, 0.1),
        )
        for item in independent
    ]
    contrast = _weighted_median(weighted)
    vulnerable_score = _weighted_median([
        (item.vulnerable_score, weight) for item, (_value, weight) in zip(independent, weighted)
    ])
    patched_score = _weighted_median([
        (item.patched_score, weight) for item, (_value, weight) in zip(independent, weighted)
    ])
    fix_coverage = max(item.fix_signature_coverage for item in independent)
    vulnerable_coverage = max(item.vulnerable_signature_coverage for item in independent)
    fix_present = fix_coverage >= config.signature_threshold
    vulnerable_present = vulnerable_coverage >= config.signature_threshold
    vulnerable_signal = (
        vulnerable_score >= config.minimum_vulnerable_score
        and contrast >= config.minimum_margin
        and (vulnerable_present or fix_coverage < config.signature_threshold)
    )
    patched_signal = (
        contrast <= -config.patched_margin or fix_present
    ) and patched_score >= config.minimum_vulnerable_score
    contradictions: list[str] = []
    if vulnerable_signal and patched_signal:
        contradictions.append("vulnerable and fix-present evidence are both strong")
        status = "uncertain"
    elif patched_signal:
        status = "patched"
    elif vulnerable_signal:
        status = "vulnerable"
    else:
        status = "uncertain"
    fix_evidence = []
    if fix_present:
        fix_evidence.append("added fix signature present")
    elif pair.fix_signature_tokens:
        fix_evidence.append("added fix signature absent")
    if vulnerable_present:
        fix_evidence.append("removed vulnerable construct retained")
    return VulnerabilityState(
        lineage_id=pair.lineage_id or "",
        fix_boundary_id=pair.fix_boundary_id,
        fix_commit_sha=pair.fix_commit_sha,
        status=status,
        vulnerable_score=vulnerable_score,
        patched_score=patched_score,
        contrast_score=contrast,
        fix_signature_coverage=fix_coverage,
        vulnerable_signature_coverage=vulnerable_coverage,
        fix_evidence=fix_evidence,
        contradictions=contradictions,
        advisories=pair.advisories,
        evidence_pair_ids=sorted({item.pair_id for item in independent}),
    )


def classify_evidence(
    evidence: list[RegionVerificationEvidence],
    aggregates: list[RegionAggregate],
    config: RegionVerifierConfig | None = None,
) -> tuple[str, LineageConfidence]:
    config = config or RegionVerifierConfig()
    if not evidence:
        return "cleared", "none"
    passing = [
        item for item in evidence
        if item.vulnerable_score >= config.minimum_vulnerable_score
        and item.vulnerable_minus_patched >= config.minimum_margin
    ]
    contradicting = [
        item for item in evidence
        if item.patched_score >= config.minimum_vulnerable_score
        and item.vulnerable_minus_patched <= -config.contradiction_margin
    ]

    # Multiple retrieved pairs and granularities can point at the same candidate
    # region. Count that source region once so repeated corpus windows do not create
    # artificial consensus.
    supporting_region_ids = {item.candidate_region_id for item in passing}
    contradicting_region_ids = {item.candidate_region_id for item in contradicting}
    decisive_region_ids = supporting_region_ids | contradicting_region_ids
    consensus_ratio = (
        len(supporting_region_ids - contradicting_region_ids) / len(decisive_region_ids)
        if decisive_region_ids else 0.0
    )
    strongest_vulnerable_margin = max(
        (item.vulnerable_minus_patched for item in passing),
        default=float("-inf"),
    )
    strongest_patched_margin = max(
        (-item.vulnerable_minus_patched for item in contradicting),
        default=float("-inf"),
    )
    has_strong_contradiction = strongest_patched_margin >= strongest_vulnerable_margin

    if (
        len(supporting_region_ids) >= config.minimum_supporting_regions
        and consensus_ratio >= config.minimum_consensus_ratio
        and not has_strong_contradiction
    ):
        best = max(passing, key=lambda item: (item.vulnerable_minus_patched, item.vulnerable_score))
        status = "flagged"
    else:
        best = max(evidence, key=lambda item: (item.vulnerable_minus_patched, item.vulnerable_score))
        status = "manual_review"
    if not passing and best.vulnerable_minus_patched <= -config.minimum_margin:
        status = "cleared"

    aggregate = next((item for item in aggregates if item.pair_id == best.pair_id), None)
    support = len(supporting_region_ids)
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
