"""Fix-boundary verdicts, identity gates, abstentions and supporting evidence."""

from __future__ import annotations

from typing import Literal

from pipeline.detection.config import HIGH_LINEAGE_CONFIDENCE_MARGIN, RegionVerifierConfig
from pipeline.models.boundary import (
    BoundaryEditEvidence, BoundaryIdentity, BoundarySupport, FallbackEvidence,
    VerificationGates, VerificationScores, VulnerabilityState, VulnerableRegionPair,
)
from pipeline.models.evidence import EditDistanceEvidence, RegionVerificationEvidence
from pipeline.models.lineage import LineageConfidence
from pipeline.models.region_retrieval import RegionAggregate
from pipeline.detection.verification.aggregation import (
    deduplicate_evidence, effective_components,
)


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
    edit: EditDistanceEvidence | None = None,
) -> VulnerabilityState:
    """Classify one fix boundary from independent, changed-region-led evidence."""

    config = config or RegionVerifierConfig()
    # Remove overlapping observations before selecting support for each reference side.
    independent = deduplicate_evidence(evidence)
    if not independent:
        return VulnerabilityState(
            status='uncertain',
            abstention_reason='NO_EVIDENCE',
            advisories=pair.advisories,
            boundary=BoundaryIdentity(
                lineage_id=pair.lineage_id or '',
                fix_boundary_id=pair.fix_boundary_id,
                fix_commit_sha=pair.origin.fix_commit_sha,
            ),
        )
    vulnerable_independent = deduplicate_evidence(evidence, side="vulnerable")
    patched_independent = deduplicate_evidence(evidence, side="patched")
    best_vulnerable = max(
        vulnerable_independent,
        key=lambda item: (
            min(effective_components(item, "vulnerable")),
            item.reference.granularity == item.candidate.granularity,
            item.comparison.ast_coverage,
            item.retrieval_similarity,
        ),
    )
    best_patched = max(
        patched_independent,
        key=lambda item: (
            min(effective_components(item, "patched")),
            item.reference.granularity == item.candidate.granularity,
            item.comparison.ast_coverage,
            item.retrieval_similarity,
        ),
    )
    # S and T must come from one real observation. Independent component
    # medians could synthesize a gate result that no candidate region achieved.
    structural_vulnerable, token_vulnerable = effective_components(
        best_vulnerable, "vulnerable"
    )
    structural_patched, token_patched = effective_components(best_patched, "patched")
    vulnerable_correspondence = (
        structural_vulnerable >= config.minimum_structure_score
        and token_vulnerable >= config.minimum_token_score
    )
    patched_correspondence = (
        structural_patched >= config.minimum_structure_score
        and token_patched >= config.minimum_token_score
    )
    # Prefer raw edit evidence when decisive, otherwise consider the contrastive anchors.
    raw_vulnerable = edit.raw_vulnerable if edit is not None else None
    raw_patched = edit.raw_patched if edit is not None else None
    raw_contrast = (
        raw_vulnerable - raw_patched
        if raw_vulnerable is not None and raw_patched is not None
        else 0.0
    )
    raw_decisive = bool(
        (vulnerable_correspondence or patched_correspondence)
        and raw_vulnerable is not None
        and raw_patched is not None
        and (
            (
                raw_vulnerable >= config.minimum_edit_side_score
                and raw_contrast >= config.minimum_edit_margin
            )
            or (
                raw_patched >= config.minimum_edit_side_score
                and raw_contrast <= -config.minimum_edit_margin
            )
        )
    )
    use_contrastive = bool(edit is not None and edit.contrastive_used and not raw_decisive)
    vulnerable_score = (
        edit.vulnerable if use_contrastive
        else raw_vulnerable if raw_vulnerable is not None
        else edit.vulnerable if edit is not None
        else 0.0
    )
    patched_score = (
        edit.patched if use_contrastive
        else raw_patched if raw_patched is not None
        else edit.patched if edit is not None
        else 0.0
    )
    contrast = vulnerable_score - patched_score
    fix_coverage = max(item.comparison.fix_signature_coverage for item in independent)
    vulnerable_coverage = max(item.comparison.vulnerable_signature_coverage for item in independent)
    fix_present = fix_coverage >= config.signature_threshold
    vulnerable_present = vulnerable_coverage >= config.signature_threshold
    signature_state = (
        "both" if fix_present and vulnerable_present
        else "fix_only" if fix_present
        else "vulnerable_only" if vulnerable_present
        else "neither"
    )
    vulnerable_signal = (
        (vulnerable_correspondence or patched_correspondence)
        and vulnerable_score >= config.minimum_edit_side_score
        and contrast >= config.minimum_edit_margin
    )
    patched_signal = (
        (vulnerable_correspondence or patched_correspondence)
        and patched_score >= config.minimum_edit_side_score
        and contrast <= -config.minimum_edit_margin
    )
    vulnerable_correspondence_score = min(structural_vulnerable, token_vulnerable)
    patched_correspondence_score = min(structural_patched, token_patched)
    # Suppress generic contrastive anchors that disagree with stronger region correspondence.
    generic_contrast_conflict = bool(
        edit is not None
        and use_contrastive
        and (
            (
                vulnerable_signal
                and edit.contrastive_vulnerable_anchor_has_identity is False
                and patched_correspondence_score > vulnerable_correspondence_score
            )
            or (
                patched_signal
                and edit.contrastive_patched_anchor_has_identity is False
                and vulnerable_correspondence_score > patched_correspondence_score
            )
        )
    )
    if generic_contrast_conflict:
        vulnerable_signal = False
        patched_signal = False
    # Check broader context and function identity before accepting an edit-based verdict.
    vulnerable_context = any(
        item.candidate.granularity in {"block", "context", "function"}
        and effective_components(item, "vulnerable")[0] >= config.minimum_structure_score
        and effective_components(item, "vulnerable")[1] >= config.minimum_token_score
        for item in evidence
    )
    patched_context = any(
        item.candidate.granularity in {"block", "context", "function"}
        and effective_components(item, "patched")[0] >= config.minimum_structure_score
        and effective_components(item, "patched")[1] >= config.minimum_token_score
        for item in evidence
    )
    candidate_function_names = {
        item.candidate.function_name
        for item in evidence
        if item.candidate.function_name
    }
    if not pair.origin.function_name or not candidate_function_names:
        function_identity_state = "unknown"
    elif pair.origin.function_name in candidate_function_names:
        function_identity_state = "match"
    else:
        function_identity_state = "conflict"
    vulnerable_anchor_has_identity = (
        edit.contrastive_vulnerable_anchor_has_identity
        if use_contrastive and edit is not None
        else edit.raw_vulnerable_anchor_has_identity
        if edit is not None and edit.raw_vulnerable_anchor_has_identity is not None
        else edit.vulnerable_anchor_has_identity if edit is not None else None
    )
    patched_anchor_has_identity = (
        edit.contrastive_patched_anchor_has_identity
        if use_contrastive and edit is not None
        else edit.raw_patched_anchor_has_identity
        if edit is not None and edit.raw_patched_anchor_has_identity is not None
        else edit.patched_anchor_has_identity if edit is not None else None
    )
    selected_anchor_has_identity = (
        vulnerable_anchor_has_identity if vulnerable_signal
        else patched_anchor_has_identity if patched_signal
        else None
    )
    selected_context = vulnerable_context if vulnerable_signal else patched_context
    boundary_identity_gate_passed = not (
        (vulnerable_signal or patched_signal)
        and not selected_context
        and function_identity_state == "conflict"
        and selected_anchor_has_identity is False
    )
    boundary_rejected = not boundary_identity_gate_passed
    # Choose a verdict, then downgrade it to uncertain if the identity gate fails.
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
    if status in {"vulnerable", "patched"} and not boundary_identity_gate_passed:
        status = "uncertain"
    structure_gate_passed = (
        structural_vulnerable >= config.minimum_structure_score
        or structural_patched >= config.minimum_structure_score
    )
    token_gate_passed = vulnerable_correspondence or patched_correspondence
    edit_strategy = (
        "contrastive" if use_contrastive else "raw" if edit is not None else "not_run"
    )
    # Report the first applicable reason for withholding a decisive verdict.
    abstention_reason = None
    if status == "uncertain":
        side_score = max(vulnerable_score, patched_score)
        margin_strength = abs(contrast)
        if boundary_rejected:
            abstention_reason = "IDENTITY_REJECTED"
        elif contradictions:
            abstention_reason = "CONTRADICTORY_EVIDENCE"
        elif generic_contrast_conflict:
            abstention_reason = "CONTRASTIVE_CONFLICT"
        elif not structure_gate_passed:
            abstention_reason = "S_FAILED"
        elif not token_gate_passed:
            abstention_reason = "T_FAILED"
        elif edit is None:
            abstention_reason = "E_NOT_RUN"
        elif (
            side_score < config.minimum_edit_side_score
            and margin_strength < config.minimum_edit_margin
        ):
            abstention_reason = "E_SIDE_AND_MARGIN_WEAK"
        elif side_score < config.minimum_edit_side_score:
            abstention_reason = "E_SIDE_WEAK"
        elif margin_strength < config.minimum_edit_margin:
            abstention_reason = "E_MARGIN_AMBIGUOUS"
        else:
            abstention_reason = "E_DIRECTION_UNRESOLVED"
    fix_evidence = []
    if signature_state == "both":
        fix_evidence.append("both vulnerable and fix signatures present; treated as non-exclusive")
    elif fix_present:
        fix_evidence.append("added fix signature present")
    elif pair.change.fix_signature_tokens:
        fix_evidence.append("added fix signature absent")
    if vulnerable_present:
        fix_evidence.append("removed vulnerable construct retained")
    if not boundary_identity_gate_passed:
        fix_evidence.append(
            "boundary identity insufficient: generic edit anchor, no contextual "
            "correspondence, and conflicting function name"
        )
    if generic_contrast_conflict:
        fix_evidence.append(
            "generic contrastive edit disagrees with stronger S/T correspondence"
        )
    vulnerable_support_count = sum(item.comparison.margin > 0 for item in independent)
    patched_support_count = sum(item.comparison.margin < 0 for item in independent)
    side_consensus_ratio = max(vulnerable_support_count, patched_support_count) / len(independent)
    return VulnerabilityState(
        status=status,
        abstention_reason=abstention_reason,
        advisories=pair.advisories,
        evidence_pair_ids=sorted({item.pair_id for item in [*independent, best_vulnerable, best_patched]}),
        boundary=BoundaryIdentity(
            lineage_id=pair.lineage_id or '',
            fix_boundary_id=pair.fix_boundary_id,
            fix_commit_sha=pair.origin.fix_commit_sha,
        ),
        edit=BoundaryEditEvidence(
            strategy=edit_strategy,
            vulnerable=vulnerable_score,
            patched=patched_score,
            margin=contrast,
            vulnerable_anchor_has_identity=vulnerable_anchor_has_identity,
            patched_anchor_has_identity=patched_anchor_has_identity,
            raw_vulnerable=edit.raw_vulnerable if edit is not None else None,
            raw_patched=edit.raw_patched if edit is not None else None,
            contrastive_vulnerable=edit.contrastive_vulnerable if edit is not None else None,
            contrastive_patched=edit.contrastive_patched if edit is not None else None,
        ),
        scores=VerificationScores(
            vulnerable_score=vulnerable_score,
            patched_score=patched_score,
            correspondence_score=max(min(structural_vulnerable, token_vulnerable), min(structural_patched, token_patched)),
            contrast_score=contrast,
            structural_vulnerable=structural_vulnerable,
            structural_patched=structural_patched,
            token_vulnerable=token_vulnerable,
            token_patched=token_patched,
        ),
        gates=VerificationGates(
            structure_gate_passed=structure_gate_passed,
            token_gate_passed=token_gate_passed,
            context_correspondence_passed=(
                vulnerable_context
                if vulnerable_signal
                else patched_context if patched_signal else vulnerable_context or patched_context
            ),
            function_identity_state=function_identity_state,
            edit_anchor_has_identity=selected_anchor_has_identity,
            boundary_identity_gate_passed=boundary_identity_gate_passed,
        ),
        fallbacks=FallbackEvidence(
            containment_attempted=(
                best_vulnerable.vulnerable.containment_attempted
                or best_patched.patched.containment_attempted
            ),
            containment_used=best_vulnerable.vulnerable.containment_used or best_patched.patched.containment_used,
        ),
        support=BoundarySupport(
            fix_signature_coverage=fix_coverage,
            vulnerable_signature_coverage=vulnerable_coverage,
            signature_evidence_state=signature_state,
            independent_region_count=len(independent),
            vulnerable_support_count=vulnerable_support_count,
            patched_support_count=patched_support_count,
            side_consensus_ratio=side_consensus_ratio,
            fix_evidence=fix_evidence,
            contradictions=contradictions,
        ),
    )


def classify_evidence(
    evidence: list[RegionVerificationEvidence],
    aggregates: list[RegionAggregate],
    config: RegionVerifierConfig | None = None,
) -> tuple[str, LineageConfidence | Literal["ambiguous"]]:
    config = config or RegionVerifierConfig()
    if not evidence:
        return "cleared", "none"
    passing = [
        item for item in evidence
        if item.vulnerable.structural >= config.minimum_structure_score
        and item.vulnerable.token >= config.minimum_token_score
        and item.comparison.margin >= config.minimum_edit_margin
    ]
    contradicting = [
        item for item in evidence
        if item.patched.structural >= config.minimum_structure_score
        and item.patched.token >= config.minimum_token_score
        and item.comparison.margin <= -config.contradiction_margin
    ]

    # Multiple retrieved pairs and granularities can point at the same candidate
    # region. Count that source region once so repeated corpus windows do not create
    # artificial consensus.
    supporting_region_ids = {item.candidate.region_id for item in passing}
    contradicting_region_ids = {item.candidate.region_id for item in contradicting}
    decisive_region_ids = supporting_region_ids | contradicting_region_ids
    consensus_ratio = (
        len(supporting_region_ids - contradicting_region_ids) / len(decisive_region_ids)
        if decisive_region_ids else 0.0
    )
    strongest_vulnerable_margin = max(
        (item.comparison.margin for item in passing),
        default=float("-inf"),
    )
    strongest_patched_margin = max(
        (-item.comparison.margin for item in contradicting),
        default=float("-inf"),
    )
    has_strong_contradiction = strongest_patched_margin >= strongest_vulnerable_margin

    if (
        len(supporting_region_ids) >= config.minimum_supporting_regions
        and consensus_ratio >= config.minimum_consensus_ratio
        and not has_strong_contradiction
    ):
        best = max(passing, key=lambda item: (item.comparison.margin, item.vulnerable.score))
        status = "flagged"
    else:
        best = max(evidence, key=lambda item: (item.comparison.margin, item.vulnerable.score))
        status = "manual_review"
    if not passing and best.comparison.margin <= -config.minimum_edit_margin:
        status = "cleared"

    aggregate = next((item for item in aggregates if item.pair_id == best.pair_id), None)
    support = len(supporting_region_ids)
    granularity_count = len(aggregate.granularities) if aggregate else 1
    if status != "flagged":
        confidence: LineageConfidence | Literal["ambiguous"] = "ambiguous" if evidence else "none"
    elif support >= 3 and granularity_count >= 2 and best.comparison.margin >= HIGH_LINEAGE_CONFIDENCE_MARGIN:
        confidence = "high"
    elif support >= 2 or granularity_count >= 2:
        confidence = "medium"
    else:
        confidence = "low"
    return status, confidence
