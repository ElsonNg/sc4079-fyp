import pytest

from eval.ablation.targeted_correspondence import recheck
from eval.ablation.priority_relationships import RevisionRelationships
from provtrail.pipeline.controller.region_extraction import extract_corpus_region_pairs, _regions_for_anchor
from provtrail.pipeline.controller.region_detection import compute_diagnostic_lines
from provtrail.pipeline.detection.verification.verifier import verify_region_pair
from provtrail.pipeline.detection.verification.classification import classify_boundary
from provtrail.pipeline.detection.verification.edit_distance import score_edit_distance
from provtrail.pipeline.detection.config import RegionVerifierConfig
from provtrail.pipeline.detection.priority import derive_priority
from provtrail.pipeline.models.boundary import BoundaryIdentity, BoundarySupport, VerificationGates, VulnerabilityState
from provtrail.pipeline.models.lineage import LineageAttribution
from provtrail.pipeline.models.result import RegionDetectionResult
from tests.test_priority_relationships import entry


V='function check(obj,key){return obj[key];}'
P='function check(obj,key){if(key === "blocked") return undefined; return obj[key];}'
CP='function renamed(value,name){return name === "blocked" ? undefined : value[name];}'
CV='function renamed(value,name){const answer=value[name]; return answer;}'


def fixture(source=CP, evidence=True):
    e=entry(V,P,"guard")
    pairs={p.pair_id:p for p in extract_corpus_region_pairs([e])}
    pair=next(p for p in pairs.values() if p.vulnerable_region.granularity=='function')
    full=_regions_for_anchor(source,[],"fixture","candidate.js")["function"]
    proof=verify_region_pair(full,pair,.9,candidate_function_name="renamed")
    diagnostics=compute_diagnostic_lines(V,P,language="javascript")
    state=classify_boundary([proof],pair,edit=score_edit_distance(source,diagnostics)) if evidence else VulnerabilityState(
        status="uncertain",abstention_reason="S_FAILED",boundary=BoundaryIdentity(
            lineage_id=pair.lineage_id,fix_boundary_id=pair.fix_boundary_id,fix_commit_sha=pair.origin.fix_commit_sha))
    value=RegionDetectionResult(candidate_id="fixture",candidate_region_count=1,retrieval_match_count=1,
        evidence=[proof] if evidence else [],vulnerability_states=[state],lineages=[LineageAttribution(
            lineage_id=pair.lineage_id,confidence="high",score=.9,repo="fixture/repo",file_path="check.js")])
    value.priority=derive_priority(value.lineages,value.vulnerability_states,[])
    return value,pairs,RevisionRelationships.from_entries([e])


@pytest.mark.parametrize("source,status,priority",[(CP,"patched","informational_lineage"),(CV,"vulnerable","automatic_vulnerability")])
def test_bounded_form_resolves_guard_rewrite_while_direct_repetition_does_not(source,status,priority):
    value,pairs,graph=fixture(source)
    assert value.priority=="manual_review"
    before=value.model_dump(mode="json")
    direct,dt=recheck(value,source,"javascript",pairs,graph,RegionVerifierConfig())
    assert direct.priority=="manual_review"
    assert dt[0]["function_comparison_already_present"]
    assert len(direct.evidence)==len(value.evidence)
    bounded,bt=recheck(value,source,"javascript",pairs,graph,RegionVerifierConfig(),bounded=True)
    assert bounded.priority==priority and bounded.vulnerability_states[0].status==status
    assert bt[0]["local"]["status"]==status
    assert value.model_dump(mode="json")==before
    assert bounded.vulnerability_states[0].boundary==value.vulnerability_states[0].boundary


def test_missing_direct_comparison_adds_evidence_without_changing_target_set():
    value,pairs,graph=fixture(evidence=False)
    changed,traces=recheck(value,CP,"javascript",pairs,graph,RegionVerifierConfig())
    assert len(changed.evidence)==1 and not traces[0]["function_comparison_already_present"]
    assert [s.boundary for s in changed.vulnerability_states]==[s.boundary for s in value.vulnerability_states]
    assert changed.vulnerability_states[0].gates.token_gate_passed


def test_generic_whole_function_mismatch_does_not_reject_boundary():
    source='function unrelated(value){return other(value);}'
    value,pairs,graph=fixture(source,evidence=False)
    changed,traces=recheck(value,source,"javascript",pairs,graph,RegionVerifierConfig(),bounded=True)
    assert changed.priority=="manual_review"
    assert changed.vulnerability_states[0].status=="uncertain"
    assert not changed.vulnerability_states[0].gates.boundary_rejected


@pytest.mark.parametrize("reason",["CONTRADICTORY_EVIDENCE","HASH_SIDE_AMBIGUOUS","CONTRASTIVE_CONFLICT"])
def test_conflicted_boundary_is_not_overwritten_by_full_form(reason):
    value,pairs,graph=fixture()
    value.vulnerability_states[0].abstention_reason=reason
    before=value.vulnerability_states[0].model_dump()
    changed,traces=recheck(value,CP,"javascript",pairs,graph,RegionVerifierConfig(),bounded=True)
    assert changed.priority=="manual_review" and not traces
    assert changed.vulnerability_states[0].model_dump()==before


def test_all_original_boundaries_remain_when_one_resolves():
    value,pairs,graph=fixture()
    unsupported=VulnerabilityState(status="uncertain",abstention_reason="E_SIDE_WEAK",
        gates=VerificationGates(token_gate_passed=True),boundary=BoundaryIdentity(
            lineage_id=value.lineages[0].lineage_id,fix_boundary_id="unknown-reference",fix_commit_sha="other"))
    value.vulnerability_states.append(unsupported)
    changed,traces=recheck(value,CP,"javascript",pairs,graph,RegionVerifierConfig(),bounded=True)
    assert changed.vulnerability_states[0].status=="patched"
    assert changed.vulnerability_states[1].model_dump()==unsupported.model_dump()
    assert changed.priority=="manual_review"
    assert traces[-1]["outcome"]=="missing_function_pair"


def test_verified_vulnerable_result_is_unchanged():
    value,pairs,graph=fixture()
    value.vulnerability_states[0].status="vulnerable"
    value.priority="automatic_vulnerability"
    changed,traces=recheck(value,CP,"javascript",pairs,graph,RegionVerifierConfig(),bounded=True)
    assert changed.model_dump(mode="json")==value.model_dump(mode="json") and not traces
