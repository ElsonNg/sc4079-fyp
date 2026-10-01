"""Direct verification of existing uncertain boundaries, without new retrieval."""
import math

from provtrail.pipeline.controller.local_correspondence import decide_local_correspondence
from provtrail.pipeline.controller.ast_correspondence import compare_ast
from provtrail.corpus.controller.extraction import compute_diagnostic_lines
from provtrail.pipeline.controller.parsing import extract_function_units
from provtrail.pipeline.controller.region_extraction import _regions_for_anchor
from provtrail.pipeline.detection.verification.verifier import verify_region_pair
from provtrail.pipeline.detection.verification.classification import classify_boundary
from provtrail.pipeline.detection.verification.edit_distance import score_edit_distance
from provtrail.pipeline.detection.revision_relationships import PROTECTED_REASONS, derive_revision_priority


def _infer_candidate_function_name(source, filename):
    units = extract_function_units(source, filename=filename)
    outer = [u for u in units if not any(o.start_byte <= u.start_byte and u.end_byte <= o.end_byte
             and (o.start_byte, o.end_byte) != (u.start_byte, u.end_byte) for o in units)]
    return outer[0].name if len(outer) == 1 else None


def _recheck_bounded(result, source, language, pairs, relationships, config, bounded=False):
    """Retain the target set and all established verdicts; only uncertain states change.

    Full-function mismatch is not identity rejection. The bounded recognizer
    must decide a reference side; unsupported/mismatching code remains uncertain.
    """
    baseline = derive_revision_priority(result, relationships)
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
    updated.priority = derive_revision_priority(updated, relationships)
    assert [s.boundary for s in updated.vulnerability_states] == [s.boundary for s in result.vulnerability_states]
    assert all(a.model_dump()==b.model_dump() for a,b in zip(result.vulnerability_states,updated.vulnerability_states)
               if a.status != "uncertain")
    return updated, traces


def verify_uncertain_boundaries(result, source, language, pairs, relationships, config):
    updated, traces = _recheck_bounded(result, source, language, pairs, relationships, config, bounded=True)
    if updated.priority != "manual_review" or result.hash_matches:
        return updated, traces
    functions = {p.fix_boundary_id:p for p in pairs.values() if p.vulnerable_region.granularity=="function"}
    direct = {t["boundary"]:t for t in traces}
    filename = {"javascript":"candidate.js", "typescript":"candidate.ts", "tsx":"candidate.tsx"}[language]
    for index, state in enumerate(updated.vulnerability_states):
        trace = direct.get(state.boundary.fix_boundary_id)
        if (state.status != "uncertain" or state.gates.boundary_rejected or state.support.contradictions
            or state.abstention_reason in PROTECTED_REASONS or not trace or not trace.get("full_function_gate")):
            continue
        if len(set((trace.get("local") or {}).get("decisive", {}).values())) > 1:
            trace["expanded_ast_skipped"] = "bounded_recognizers_disagree"
            continue
        pair = functions[state.boundary.fix_boundary_id]
        answer = compare_ast(pair.vulnerable_region.source, pair.patched_region.source, source, filename,
                             remove_noop=False)
        trace["expanded_ast"] = answer
        trace["before_expanded"] = state.status
        if answer["status"] in {"vulnerable", "patched"}:
            updates = dict(local_correspondence_attempted=True, local_correspondence_used=True,
                           local_correspondence_status=answer["status"], local_correspondence_methods=["binding_ast"],
                           local_correspondence_reason=answer["reason"],
                           local_correspondence_prior_abstention_reason=state.abstention_reason)
            state = state.model_copy(update=dict(status=answer["status"], abstention_reason=None,
                support=state.support.model_copy(update=dict(fix_evidence=[*state.support.fix_evidence,
                    "Whole-function binding AST correspondence: " + answer["normalization"]])),
                fallbacks=state.fallbacks.model_copy(update=updates)))
            updated.vulnerability_states[index] = state
            trace["after"] = state.status
            trace["after_reason"] = state.abstention_reason
    updated.priority = derive_revision_priority(updated, relationships)
    assert [s.boundary for s in result.vulnerability_states] == [s.boundary for s in updated.vulnerability_states]
    assert all(a.model_dump()==b.model_dump() for a,b in zip(result.vulnerability_states,updated.vulnerability_states)
               if a.status != "uncertain")
    return updated, traces
