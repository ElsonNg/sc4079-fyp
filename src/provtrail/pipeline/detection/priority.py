"""Choose reporting priority from lineage and fix-boundary decisions."""

from provtrail.pipeline.models.boundary import VulnerabilityState
from provtrail.pipeline.models.evidence import PackageApplicability
from provtrail.pipeline.models.lineage import LineageAttribution


def derive_priority(
    lineages: list[LineageAttribution],
    states: list[VulnerabilityState],
    applicabilities: list[PackageApplicability],
) -> str:
    credible = {item.lineage_id for item in lineages if item.confidence in {"high", "medium"}}
    scoped = [item for item in states if item.boundary.lineage_id in credible]
    # Completing S -> T -> E is stronger evidence than retrieval-derived lineage
    # confidence. Do not let a low lineage score veto an already verified boundary.
    vulnerable = [item for item in states if item.status == "vulnerable"]
    if any(not item.support.contradictions for item in vulnerable):
        # Package ownership explains how code entered the project. It does not
        # invalidate strong code-level evidence. Keep applicability as report
        # context and reserve manual review for genuinely ambiguous boundaries.
        return "automatic_vulnerability"
    if vulnerable:
        return "manual_review"
    patched = [item for item in states if item.status == "patched"]
    unresolved = [
        item for item in scoped
        if item.status == "uncertain"
        and not item.gates.boundary_rejected
    ]
    strong_uncertainty = [
        item for item in unresolved
        if item.gates.token_gate_passed or bool(item.support.contradictions)
    ]
    # A retrieved boundary that never completed S/T is weak alternative-search
    # noise. It must not override an independently verified patched boundary.
    if patched and not strong_uncertainty:
        return "informational_lineage"
    if strong_uncertainty:
        return "manual_review"
    if unresolved:
        return "manual_review"
    return "none"
