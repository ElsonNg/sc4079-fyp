from unittest.mock import patch
import pytest
from eval.ablation import expanded_correspondence as expanded
from provtrail.pipeline.detection.config import RegionVerifierConfig
from tests.test_targeted_correspondence import fixture, CP


def uncertain_fixture():
    value,pairs,graph=fixture()
    proof=dict(boundary=value.vulnerability_states[0].boundary.fix_boundary_id, full_function_gate=True,
               local=dict(decisive={}), after="uncertain",after_reason="E_SIDE_WEAK")
    return value,pairs,graph,proof


def test_ast_verdict_preserves_boundary_and_is_separate_evidence():
    value,pairs,graph,proof=uncertain_fixture()
    before=value.model_dump(mode="json")
    with patch.object(expanded,"bounded_recheck",return_value=(value.model_copy(deep=True),[proof])), \
         patch.object(expanded,"compare_ast",return_value=dict(status="patched",reason="whole_function_binding_correspondence",normalization="bindings")):
        updated,traces=expanded.recheck(value,CP,"javascript",pairs,graph,RegionVerifierConfig())
    assert updated.priority=="informational_lineage"
    assert updated.vulnerability_states[0].fallbacks.local_correspondence_methods==["binding_ast"]
    assert updated.vulnerability_states[0].boundary==value.vulnerability_states[0].boundary
    assert value.model_dump(mode="json")==before


@pytest.mark.parametrize("reason",["CONTRADICTORY_EVIDENCE","CONTRASTIVE_CONFLICT","HASH_SIDE_AMBIGUOUS"])
def test_expanded_never_overwrites_a_protected_conflict(reason):
    value,pairs,graph,proof=uncertain_fixture()
    value.vulnerability_states[0].abstention_reason=reason
    with patch.object(expanded,"bounded_recheck",return_value=(value.model_copy(deep=True),[proof])), patch.object(expanded,"compare_ast") as call:
        updated,_=expanded.recheck(value,CP,"javascript",pairs,graph,RegionVerifierConfig())
    call.assert_not_called()
    assert updated.priority=="manual_review"


@pytest.mark.parametrize("kind",["gate_failed","bounded_disagreed","identity_rejected"])
def test_expanded_requires_full_function_gate_and_agreeing_evidence(kind):
    value,pairs,graph,proof=uncertain_fixture()
    if kind=="gate_failed":proof["full_function_gate"]=False
    elif kind=="bounded_disagreed":proof["local"]["decisive"]={"guard":"patched","order":"vulnerable"}
    else:value.vulnerability_states[0].gates.boundary_identity_gate_passed=False
    with patch.object(expanded,"bounded_recheck",return_value=(value.model_copy(deep=True),[proof])), patch.object(expanded,"compare_ast") as call:
        updated,_=expanded.recheck(value,CP,"javascript",pairs,graph,RegionVerifierConfig())
    call.assert_not_called()
    assert updated.vulnerability_states[0].status=="uncertain"


def test_mismatch_cannot_exclude_a_competing_boundary():
    value,pairs,graph,proof=uncertain_fixture()
    with patch.object(expanded,"bounded_recheck",return_value=(value.model_copy(deep=True),[proof])), \
         patch.object(expanded,"compare_ast",return_value=dict(status="uncertain",reason="matches_neither_reference")):
        updated,_=expanded.recheck(value,CP,"javascript",pairs,graph,RegionVerifierConfig())
    assert updated.priority=="manual_review" and not updated.vulnerability_states[0].gates.boundary_rejected
