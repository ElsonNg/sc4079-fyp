"""Resolve existing uncertainty using additional whole-function correspondence."""
from eval.ablation.ast_correspondence import compare_ast
from eval.ablation.priority_policy import PROTECTED_REASONS
from eval.ablation.priority_relationships import experimental_priority
from eval.ablation.targeted_correspondence import recheck as bounded_recheck


ARMS = ("bounded_baseline", "expanded_ast", "expanded_ast_noop")


def recheck(result, source, language, pairs, relationships, config, *, mode="expanded_ast_noop"):
    assert mode in ARMS
    updated, traces = bounded_recheck(result, source, language, pairs, relationships, config, bounded=True)
    if mode == "bounded_baseline" or updated.priority != "manual_review" or result.hash_matches:
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
                             remove_noop=mode=="expanded_ast_noop")
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
    updated.priority = experimental_priority(updated, relationships)
    assert [s.boundary for s in result.vulnerability_states] == [s.boundary for s in updated.vulnerability_states]
    assert all(a.model_dump()==b.model_dump() for a,b in zip(result.vulnerability_states,updated.vulnerability_states)
               if a.status != "uncertain")
    return updated, traces
