"""Direct verification of existing uncertain boundaries, without new retrieval."""
import math

from provtrail.pipeline.controller.local_correspondence import decide_local_correspondence
from provtrail.pipeline.controller.region_detection import compute_diagnostic_lines, _infer_candidate_function_name
from provtrail.pipeline.controller.region_extraction import _regions_for_anchor
from provtrail.pipeline.detection.verification.verifier import verify_region_pair
from provtrail.pipeline.detection.verification.classification import classify_boundary
from provtrail.pipeline.detection.verification.edit_distance import score_edit_distance
from eval.ablation.priority_policy import PROTECTED_REASONS
from eval.ablation.priority_relationships import experimental_priority


ARMS = ("direct_function", "direct_plus_bounded")


def recheck(result, source, language, pairs, relationships, config, bounded=False):
    """Retain the target set and all established verdicts; only uncertain states change.

    Full-function mismatch is not identity rejection. The bounded recognizer
    must decide a reference side; unsupported/mismatching code remains uncertain.
    """
    baseline = experimental_priority(result, relationships)
    assert baseline == result.priority, "Relationship baseline differs from saved result"
    if baseline != "manual_review" or result.hash_matches:
        return result.model_copy(deep=True), []
    filename = {"javascript": "candidate.js", "typescript": "candidate.ts", "tsx": "candidate.tsx"}[language]
    full = _regions_for_anchor(source, [], "targeted:" + str(result.candidate_id), filename)["function"]
    name = _infer_candidate_function_name(source, filename)
    functions = {p.fix_boundary_id: p for p in pairs.values() if p.vulnerable_region.granularity == "function"}
    credible = {l.lineage_id for l in result.lineages if l.confidence in {"high", "medium"}}
    states, traces, additional = [], [], []
    for old in result.vulnerability_states:
        if (old.status != "uncertain" or old.gates.boundary_rejected or old.support.contradictions
            or old.abstention_reason in PROTECTED_REASONS or old.boundary.lineage_id not in credible):
            states.append(old.model_copy(deep=True))
            continue
        pair = functions.get(old.boundary.fix_boundary_id)
        if pair is None:
            states.append(old.model_copy(deep=True))
            traces.append(dict(boundary=old.boundary.fix_boundary_id, outcome="missing_function_pair"))
            continue
        original = [e for e in result.evidence if pairs[e.pair_id].fix_boundary_id == old.boundary.fix_boundary_id]
        direct = verify_region_pair(full, pair, retrieval_similarity=0.0, config=config, candidate_function_name=name)
        prior_full = [e for e in original if e.candidate.granularity == "function" and e.pair_id == pair.pair_id]
        for prior in prior_full:
            assert all(math.isclose(getattr(prior_side, k), getattr(new_side, k), abs_tol=1e-12)
                       for prior_side, new_side in ((prior.vulnerable, direct.vulnerable), (prior.patched, direct.patched))
                       for k in ("structural", "token")), "Full-function recheck unexpectedly changed an existing comparison"
        scoped = original if prior_full else [*original, direct]
        if not prior_full:
            additional.append(direct)
        state = classify_boundary(scoped, pair, config)
        if state.gates.token_gate_passed:
            diagnostic = compute_diagnostic_lines(pair.vulnerable_region.source, pair.patched_region.source, language=language)
            edit = score_edit_distance(source, diagnostic)
            state = classify_boundary(scoped, pair, config, edit=edit)
        function_gate = any(s.structural >= config.minimum_structure_score and s.token >= config.minimum_token_score
                            for s in (direct.vulnerable, direct.patched))
        local = None
        if (bounded and state.status == "uncertain" and function_gate and state.gates.token_gate_passed
            and not state.gates.boundary_rejected and not state.support.contradictions
            and state.abstention_reason not in PROTECTED_REASONS):
            local = decide_local_correspondence(pair.vulnerable_region.source, pair.patched_region.source, source, filename)
            updates = dict(local_correspondence_attempted=True, local_correspondence_status=local["status"],
                           local_correspondence_methods=sorted(local["decisive"]), local_correspondence_reason=local["reason"],
                           local_correspondence_prior_abstention_reason=state.abstention_reason)
            if local["status"] in {"patched", "vulnerable"}:
                updates["local_correspondence_used"] = True
                state = state.model_copy(update={"status": local["status"], "abstention_reason": None,
                    "support": state.support.model_copy(update={"fix_evidence": [*state.support.fix_evidence,
                        "Targeted whole-function correspondence: " + ", ".join(sorted(local["decisive"]))]})})
            state = state.model_copy(update={"fallbacks": state.fallbacks.model_copy(update=updates)})
        states.append(state)
        traces.append(dict(boundary=old.boundary.fix_boundary_id, before=old.status, after=state.status,
                           prior_reason=old.abstention_reason, after_reason=state.abstention_reason,
                           function_comparison_already_present=bool(prior_full), full_function_gate=function_gate,
                           direct_scores=direct.to_record(), local=local))
    updated = result.model_copy(deep=True, update={"vulnerability_states": states, "evidence": [*result.evidence, *additional]})
    updated.priority = experimental_priority(updated, relationships)
    assert [s.boundary for s in updated.vulnerability_states] == [s.boundary for s in result.vulnerability_states]
    assert all(a.model_dump()==b.model_dump() for a,b in zip(result.vulnerability_states,updated.vulnerability_states)
               if a.status != "uncertain")
    return updated, traces
