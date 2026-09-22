import pytest
from eval.common import DEFAULT_SNAPSHOT_DB
from eval.tier2.routing_checks import check,selected
from eval.tier2.additional_checks import assess_observations
from provtrail.corpus.integrations.sqlite_store import load_entries
from eval.tier2.extend_validation import build_records
from eval.ablation.common import entry_identity,identity
ENTRIES=load_entries(DEFAULT_SNAPSHOT_DB)
TARGETS=[e for e in ENTRIES if selected(e)]

@pytest.mark.parametrize('entry',TARGETS,ids=lambda e:f'{e.advisory.package_name}-{e.origin.function_name}-{e.origin.fix_commit_sha[:8]}')
def test_original_witness_and_opposite_label(entry):
    for side,source in [('flagged',entry.vulnerable_function),('cleared',entry.patched_function)]:
        result=check(dict(candidate_source=source,expected_status=side),entry,ENTRIES)
        assert result['status']=='pass',result
        obs=result['execution']['observations']
        assert obs[0]['value']['witness'] is False and obs[1]['value']['witness'] is True
        assert assess_observations(obs,'cleared' if side=='flagged' else 'flagged')=='behaviour_mismatch'

@pytest.mark.parametrize('package,function,source',[
    ('axios','isAbsoluteURL','function(){return true;}'),
    ('electron','canAccessWindow','function(){return false;}'),
    ('liquidjs','candidates','function*(){yield "/root/file.liquid";}'),
])
def test_boundary_only_implementation_fails_controls(package,function,source):
    entry=next(e for e in TARGETS if e.advisory.package_name==package and e.origin.function_name==function)
    result=check(dict(candidate_source=source,expected_status='cleared'),entry,ENTRIES)
    assert result['execution']['observations'][2]['value']['witness'] is True
    assert result['status']=='behaviour_mismatch'

def test_unknown_program_entry_is_not_a_syntax_defect():
    entry=next(e for e in TARGETS if e.advisory.package_name=='axios')
    result=check(dict(candidate_source='const a=()=>true; const b=()=>false;',expected_status='cleared'),entry,ENTRIES)
    assert result['status']=='inconclusive_candidate_adapter'

@pytest.mark.parametrize('candidate_id,status',[('L049','pass'),('L136','behaviour_mismatch'),('LN141','behaviour_mismatch'),('LN286','behaviour_mismatch')])
def test_observed_transform_defects_and_pure_getter_reordering(candidate_id,status):
    record=next(r for r in build_records(ENTRIES) if r['candidate_id']==candidate_id)
    entry=next(e for e in TARGETS if entry_identity(e)==identity(record))
    result=check(record,entry,ENTRIES)
    assert result['status']==status,result
