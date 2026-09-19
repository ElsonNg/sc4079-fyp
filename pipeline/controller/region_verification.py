"""Localized AST/token verification for retrieved vulnerable regions."""

from __future__ import annotations

import difflib
import re

from pipeline.controller.edit_distance import EditDistanceEvidence, fuzzy_substring_similarity
from pipeline.controller.parsing import normalize_source
from pipeline.detection.config import RegionVerifierConfig
from pipeline.models.boundary import (
    BoundaryEditEvidence,
    BoundaryIdentity,
    BoundarySupport,
    FallbackEvidence,
    VerificationGates,
    VerificationScores,
    VulnerabilityState,
    VulnerableRegionPair,
)
from pipeline.models.evidence import (
    CandidateEvidenceReference,
    PairedEvidenceReference,
    ReferenceSideEvidence,
    RegionComparison,
    RegionVerificationEvidence,
)
from pipeline.models.lineage import LineageConfidence
from pipeline.models.region import AstRegion
from pipeline.models.region_retrieval import RegionAggregate

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")
_API_ANCHOR_SEPARATOR_RE = re.compile(r"\?\.|\.")
_KEYWORDS = {
    "if", "else", "for", "while", "do", "switch", "case", "return", "throw", "try",
    "catch", "finally", "const", "let", "var", "new", "function", "class", "await",
    "async", "true", "false", "null", "undefined", "this", "typeof", "instanceof",
}


def _ratio(left: list[str], right: list[str]) -> float:
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    if left == right:
        return 1.0

    # Large generated/bundled functions commonly differ in only a tiny interior
    # region. Running SequenceMatcher with autojunk disabled over the complete
    # 100k+ token/shape sequences can become effectively quadratic. Peel off the
    # guaranteed identical edges, compare only the changed core, then fold the
    # common elements back into the standard 2*M/(len(a)+len(b)) ratio.
    prefix = 0
    shared_limit = min(len(left), len(right))
    while prefix < shared_limit and left[prefix] == right[prefix]:
        prefix += 1

    suffix = 0
    suffix_limit = shared_limit - prefix
    while suffix < suffix_limit and left[-1 - suffix] == right[-1 - suffix]:
        suffix += 1

    left_end = len(left) - suffix if suffix else len(left)
    right_end = len(right) - suffix if suffix else len(right)
    left_core = left[prefix:left_end]
    right_core = right[prefix:right_end]
    core_total = len(left_core) + len(right_core)
    core_ratio = (
        difflib.SequenceMatcher(
            a=left_core,
            b=right_core,
            autojunk=core_total > 4096,
        ).ratio()
        if core_total
        else 1.0
    )
    common_matches = prefix + suffix
    return (2 * common_matches + core_ratio * core_total) / (len(left) + len(right))


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
    # A regular expression is executable matching logic rather than an opaque
    # data literal. Keep its complete pattern and flags as an explicit token so
    # security fixes such as ``[^)]`` -> ``[^()]`` survive role normalization.
    # Ordinary strings and numbers continue to collapse to LIT above.
    tokens.extend(
        f"REGEX:{value}"
        for value in region.literals
        if value.startswith("/")
    )
    return tokens


def _structural_score(candidate: AstRegion, reference: AstRegion) -> float:
    shape = _ratio(candidate.ast_shape, reference.ast_shape)
    path = _ratio(candidate.ast_path, reference.ast_path)
    return 0.50 * shape + 0.50 * path


def _token_score(candidate: AstRegion, reference: AstRegion) -> float:
    role_score = _ratio(_role_tokens(candidate), _role_tokens(reference))
    return role_score


def _containment_score(
    left: list[str], right: list[str], max_cells: int | None = None
) -> tuple[float, float]:
    """Score the shorter sequence inside the longer, guarded by size coverage."""
    if not left or not right:
        return 0.0, 0.0
    shorter, longer = (left, right) if len(left) <= len(right) else (right, left)
    coverage = len(shorter) / len(longer)
    if max_cells is not None and len(shorter) * len(longer) > max_cells:
        return 0.0, coverage
    return fuzzy_substring_similarity(shorter, longer), coverage


def _containment_components(
    candidate: AstRegion, reference: AstRegion, max_cells: int | None = None
) -> tuple[float, float, float]:
    shape, shape_coverage = _containment_score(candidate.ast_shape, reference.ast_shape, max_cells)
    path, path_coverage = _containment_score(candidate.ast_path, reference.ast_path, max_cells)
    token, token_coverage = _containment_score(
        _role_tokens(candidate), _role_tokens(reference), max_cells
    )
    return 0.5 * shape + 0.5 * path, token, min(shape_coverage, path_coverage, token_coverage)


def _normalize_api_anchor(value: str) -> str:
    """Ignore a renameable receiver while retaining the API/property path."""
    compact = re.sub(r"\s+", "", value)
    parts = _API_ANCHOR_SEPARATOR_RE.split(compact)
    if len(parts) >= 2 and all(_IDENTIFIER_RE.match(part) for part in parts):
        if parts[0] not in {"this", "super"}:
            parts[0] = "ID"
        return ".".join(parts)
    return compact


def _api_anchor_score(candidate: AstRegion, reference: AstRegion) -> float | None:
    calls = _jaccard(
        [_normalize_api_anchor(value) for value in candidate.calls],
        [_normalize_api_anchor(value) for value in reference.calls],
    )
    members = _jaccard(
        [_normalize_api_anchor(value) for value in candidate.member_accesses],
        [_normalize_api_anchor(value) for value in reference.member_accesses],
    )
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
    language: str,
) -> tuple[float, float, float, float | None, float | None, bool]:
    structural = _structural_score(candidate, reference)
    token = _token_score(candidate, reference)
    api_anchor = _api_anchor_score(candidate, reference)
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
        score = min(structural, token, local)
    else:
        # A compatibility summary of the staged gates, not an averaged score.
        score = min(structural, token)
    return score, structural, token, api_anchor, local, fallback


def verify_region_pair(
    candidate_region: AstRegion,
    pair: VulnerableRegionPair,
    retrieval_similarity: float,
    config: RegionVerifierConfig | None = None,
    model_id: str | None = None,
    use_embedding_alignment: bool = False,
    language: str = "javascript",
    candidate_function_name: str | None = None,
) -> RegionVerificationEvidence:
    config = config or RegionVerifierConfig()
    vuln_score, vuln_struct, vuln_token, vuln_api_anchor, vuln_local, vuln_fallback = _side_score(
        candidate_region,
        pair.vulnerable_region,
        config,
        model_id,
        use_embedding_alignment,
        language,
    )
    patch_score, patch_struct, patch_token, patch_api_anchor, patch_local, patch_fallback = _side_score(
        candidate_region,
        pair.patched_region,
        config,
        model_id,
        use_embedding_alignment,
        language,
    )
    containment_vuln_struct, containment_vuln_token, containment_vuln_coverage = (
        _containment_components(
            candidate_region, pair.vulnerable_region, config.max_containment_cells
        )
    )
    containment_patch_struct, containment_patch_token, containment_patch_coverage = (
        _containment_components(
            candidate_region, pair.patched_region, config.max_containment_cells
        )
    )
    containment_vuln_attempted = (
        config.include_containment_fallback
        and not (
            vuln_struct >= config.minimum_structure_score
            and vuln_token >= config.minimum_token_score
        )
    )
    containment_vuln_used = (
        containment_vuln_attempted
        and containment_vuln_coverage >= config.minimum_containment_coverage
        and containment_vuln_struct >= config.minimum_structure_score
        and containment_vuln_token >= config.minimum_token_score
    )
    containment_patch_attempted = (
        config.include_containment_fallback
        and not (
            patch_struct >= config.minimum_structure_score
            and patch_token >= config.minimum_token_score
        )
    )
    containment_patch_used = (
        containment_patch_attempted
        and containment_patch_coverage >= config.minimum_containment_coverage
        and containment_patch_struct >= config.minimum_structure_score
        and containment_patch_token >= config.minimum_token_score
    )
    if containment_vuln_used:
        vuln_score = min(containment_vuln_struct, containment_vuln_token)
    if containment_patch_used:
        patch_score = min(containment_patch_struct, containment_patch_token)
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
        retrieval_similarity=retrieval_similarity,
        candidate=CandidateEvidenceReference(
            region_id=candidate_region.region_id,
            span=candidate_region.span,
            granularity=candidate_region.granularity,
            function_name=candidate_function_name,
        ),
        reference=PairedEvidenceReference(
            vulnerable_region_id=pair.vulnerable_region.region_id,
            patched_region_id=pair.patched_region.region_id,
            granularity=pair.vulnerable_region.granularity,
        ),
        vulnerable=ReferenceSideEvidence(
            structural=vuln_struct,
            token=vuln_token,
            api_anchor=vuln_api_anchor,
            local_alignment=vuln_local,
            score=vuln_score,
            containment_structural=containment_vuln_struct,
            containment_token=containment_vuln_token,
            containment_coverage=containment_vuln_coverage,
            containment_used=containment_vuln_used,
            containment_attempted=containment_vuln_attempted,
        ),
        patched=ReferenceSideEvidence(
            structural=patch_struct,
            token=patch_token,
            api_anchor=patch_api_anchor,
            local_alignment=patch_local,
            score=patch_score,
            containment_structural=containment_patch_struct,
            containment_token=containment_patch_token,
            containment_coverage=containment_patch_coverage,
            containment_used=containment_patch_used,
            containment_attempted=containment_patch_attempted,
        ),
        comparison=RegionComparison(
            correspondence_score=max(vuln_score, patch_score),
            margin=margin,
            ast_coverage=coverage,
            fix_signature_coverage=signature_coverage(pair.change.fix_signature_tokens),
            vulnerable_signature_coverage=signature_coverage(pair.change.vulnerable_signature_tokens),
            alignment_fallback_used=vuln_fallback or patch_fallback or containment_vuln_used or containment_patch_used,
        ),
    )


_GRANULARITY_WEIGHT = {"changed": 4.0, "block": 3.0, "context": 2.0, "function": 1.0}


def _overlap(left: RegionVerificationEvidence, right: RegionVerificationEvidence) -> bool:
    if left.candidate.span is None or right.candidate.span is None:
        return left.candidate.region_id == right.candidate.region_id
    return (
        left.candidate.span.start_byte < right.candidate.span.end_byte
        and right.candidate.span.start_byte < left.candidate.span.end_byte
    )


def _effective_components(
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
        vulnerable = min(_effective_components(item, "vulnerable"))
        patched = min(_effective_components(item, "patched"))
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
            min(_effective_components(item, "vulnerable")),
            item.reference.granularity == item.candidate.granularity,
            item.comparison.ast_coverage,
            item.retrieval_similarity,
        ),
    )
    best_patched = max(
        patched_independent,
        key=lambda item: (
            min(_effective_components(item, "patched")),
            item.reference.granularity == item.candidate.granularity,
            item.comparison.ast_coverage,
            item.retrieval_similarity,
        ),
    )
    # S and T must come from one real observation. Independent component
    # medians could synthesize a gate result that no candidate region achieved.
    structural_vulnerable, token_vulnerable = _effective_components(
        best_vulnerable, "vulnerable"
    )
    structural_patched, token_patched = _effective_components(best_patched, "patched")
    vulnerable_correspondence = (
        structural_vulnerable >= config.minimum_structure_score
        and token_vulnerable >= config.minimum_token_score
    )
    patched_correspondence = (
        structural_patched >= config.minimum_structure_score
        and token_patched >= config.minimum_token_score
    )
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
    vulnerable_context = any(
        item.candidate.granularity in {"block", "context", "function"}
        and _effective_components(item, "vulnerable")[0] >= config.minimum_structure_score
        and _effective_components(item, "vulnerable")[1] >= config.minimum_token_score
        for item in evidence
    )
    patched_context = any(
        item.candidate.granularity in {"block", "context", "function"}
        and _effective_components(item, "patched")[0] >= config.minimum_structure_score
        and _effective_components(item, "patched")[1] >= config.minimum_token_score
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
) -> tuple[str, LineageConfidence]:
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
        confidence: ProvenanceConfidence = "ambiguous" if evidence else "none"
    elif support >= 3 and granularity_count >= 2 and best.comparison.margin >= 0.15:
        confidence = "high"
    elif support >= 2 or granularity_count >= 2:
        confidence = "medium"
    else:
        confidence = "low"
    return status, confidence
