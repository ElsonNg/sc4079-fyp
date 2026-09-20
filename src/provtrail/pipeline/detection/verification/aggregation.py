"""Select independent, coherent observations from overlapping region matches."""

from __future__ import annotations

from provtrail.pipeline.models.evidence import RegionVerificationEvidence


_GRANULARITY_WEIGHT = {"changed": 4.0, "block": 3.0, "context": 2.0, "function": 1.0}


def _overlap(left: RegionVerificationEvidence, right: RegionVerificationEvidence) -> bool:
    if left.candidate.span is None or right.candidate.span is None:
        return left.candidate.region_id == right.candidate.region_id
    return (
        left.candidate.span.start_byte < right.candidate.span.end_byte
        and right.candidate.span.start_byte < left.candidate.span.end_byte
    )


def effective_components(
    item: RegionVerificationEvidence,
    side: str,
) -> tuple[float, float]:
    if side == "vulnerable":
        if item.vulnerable.containment_used:
            return (
                item.vulnerable.containment_structural or 0.0,
                item.vulnerable.containment_token or 0.0,
            )
        return item.vulnerable.structural, item.vulnerable.token
    if item.patched.containment_used:
        return (
            item.patched.containment_structural or 0.0,
            item.patched.containment_token or 0.0,
        )
    return item.patched.structural, item.patched.token


def deduplicate_evidence(
    evidence: list[RegionVerificationEvidence],
    side: str | None = None,
) -> list[RegionVerificationEvidence]:
    """Keep the strongest coherent alignment for each overlapping source area.

    Reference granularities are alternative explanations of one candidate span.
    Prefer actual S/T correspondence before using granularity or directional
    margin, so a slightly more decisive mismatch cannot displace an exact match.
    """

    def correspondence(item: RegionVerificationEvidence) -> float:
        vulnerable = min(effective_components(item, "vulnerable"))
        patched = min(effective_components(item, "patched"))
        if side == "vulnerable":
            return vulnerable
        if side == "patched":
            return patched
        return max(vulnerable, patched)

    ordered = sorted(
        evidence,
        key=lambda item: (
            -correspondence(item),
            -(item.reference.granularity == item.candidate.granularity),
            -_GRANULARITY_WEIGHT[item.candidate.granularity],
            -item.comparison.ast_coverage,
            -item.retrieval_similarity,
            item.candidate.region_id,
        ),
    )
    selected: list[RegionVerificationEvidence] = []
    for item in ordered:
        if not any(_overlap(item, existing) for existing in selected):
            selected.append(item)
    return selected
