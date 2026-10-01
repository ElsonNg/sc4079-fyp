"""Experimental aggregation only; production boundary verification is unchanged."""
from provtrail.pipeline.detection.priority import derive_priority


POLICY = "patch_specific_uncertainty_v1"
PROTECTED_REASONS = {"CONTRADICTORY_EVIDENCE", "CONTRASTIVE_CONFLICT", "HASH_SIDE_AMBIGUOUS"}


def patch_specific_support(state, minimum_edit_side_score):
    """Require a named edit anchor on a side meeting the existing edit threshold.

    This is an operational proxy for patch correspondence, not proof of origin.
    Unknown anchor identity and function names alone do not qualify.
    """
    return state.gates.token_gate_passed and any(
        identity is True and score is not None and score >= minimum_edit_side_score
        for identity, score in (
            (state.edit.vulnerable_anchor_has_identity, state.edit.vulnerable),
            (state.edit.patched_anchor_has_identity, state.edit.patched),
        )
    )


def experimental_priority(result, minimum_edit_side_score):
    baseline = derive_priority(result.lineages, result.vulnerability_states, result.package_applicabilities)
    states = result.vulnerability_states
    # Hash decisions, vulnerable findings, and cases without a verified patch
    # keep the existing policy. No boundary verdict is edited.
    if result.hash_matches or any(s.status == "vulnerable" for s in states):
        return baseline
    if not any(s.status == "patched" for s in states):
        return baseline
    uncertain = [s for s in states if s.status == "uncertain" and not s.gates.boundary_rejected]
    if any(s.support.contradictions or s.abstention_reason in PROTECTED_REASONS for s in uncertain):
        return "manual_review"
    credible = {l.lineage_id for l in result.lineages if l.confidence in {"high", "medium"}}
    if any(s.boundary.lineage_id in credible and patch_specific_support(s, minimum_edit_side_score)
           for s in uncertain):
        return "manual_review"
    return "informational_lineage"
