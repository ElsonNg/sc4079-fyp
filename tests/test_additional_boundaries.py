import pytest

from eval.ablation.common import digest, entry_identity, read_jsonl
from eval.common import DEFAULT_SNAPSHOT_DB
from eval.tier2.additional_checks import check, selected, assess_observations
from provtrail.corpus.integrations.sqlite_store import load_entries

ENTRIES=load_entries(DEFAULT_SNAPSHOT_DB)
TARGETS=[e for e in ENTRIES if selected(e)]


@pytest.mark.parametrize('entry',TARGETS,ids=lambda e:f'{e.advisory.package_name}-{e.origin.function_name}-{e.origin.fix_commit_sha[:8]}')
def test_real_originals_show_security_witness_and_reject_swapped_labels(entry):
    for side,source in [('flagged',entry.vulnerable_function),('cleared',entry.patched_function)]:
        result=check(dict(candidate_source=source,expected_status=side),entry,ENTRIES)
        assert result['status']=='pass',result
        observations=result['execution']['observations']
        assert observations[0]['value']['witness'] is False
        assert observations[1]['value']['witness'] is True
        opposite='cleared' if side=='flagged' else 'flagged'
        assert assess_observations(observations,opposite)=='behaviour_mismatch'


def test_missing_exact_fix_helper_does_not_run_with_other_revision():
    entry=next(e for e in TARGETS if e.origin.function_name=='redirect')
    wrong_context=[e for e in ENTRIES if e.origin.fix_commit_sha!=entry.origin.fix_commit_sha]
    result=check(dict(candidate_source=entry.patched_function,expected_status='cleared'),entry,wrong_context)
    assert result['status']=='inconclusive_missing_matching_helper'


def test_arbitrary_original_difference_is_not_security_evidence():
    observations=[dict(ok=True,value=dict(witness=False,other=1)),dict(ok=True,value=dict(witness=False,other=2)),dict(ok=True,value=dict(witness=False,other=2))]
    assert assess_observations(observations,'cleared')=='inconclusive_security_oracle'


@pytest.mark.parametrize('candidate_id',['L089','L142'])
def test_known_conditional_and_operation_order_defects_are_detected(candidate_id):
    records=read_jsonl('eval/frozen/tier2-v2/quarantine.jsonl')
    record=next(r for r in records if r['candidate_id']==candidate_id)
    key=tuple(record['corpus_entry'][k] for k in ('ghsa_id','fix_commit_sha','file_path','function_name'))
    entry=next(e for e in ENTRIES if entry_identity(e)==key)
    result=check(record,entry,ENTRIES)
    assert result['status']=='behaviour_mismatch',result


def test_wrapping_real_read_promise_does_not_fail_due_to_stub_callback_identity():
    record=next(r for r in read_jsonl('eval/frozen/tier2-v2/quarantine.jsonl') if r['candidate_id']=='L143')
    entry=next(e for e in ENTRIES if e.advisory.package_name=='fastify' and e.origin.function_name=='onRead')
    assert check(record,entry,ENTRIES)['status']=='pass'
