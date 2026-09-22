import copy
from pathlib import Path

import pytest

from eval.ablation.common import read_jsonl,entry_identity,file_hash
from eval.common import DEFAULT_SNAPSHOT_DB
from eval.tier2.context_checks import check,selected,extract,load_context,SOURCES
from eval.tier2.context_checks import callable_adapter,comparison_view
from eval.tier2.extend_validation import build_records
from eval.tier2.revalidate import identity
from eval.tier2.additional_checks import assess_observations
from provtrail.corpus.integrations.sqlite_store import load_entries

ENTRIES=load_entries(DEFAULT_SNAPSHOT_DB)
TARGETS=[e for e in ENTRIES if selected(e)]


@pytest.mark.parametrize('entry',TARGETS,ids=lambda e:f'{e.advisory.package_name}-{e.origin.function_name}-{e.origin.fix_commit_sha[:8]}')
def test_original_security_witness_and_swapped_side_rejection(entry):
    for side,source in [('flagged',entry.vulnerable_function),('cleared',entry.patched_function)]:
        result=check(dict(candidate_source=source,expected_status=side),entry,ENTRIES)
        assert result['status']=='pass',result
        observations=result['execution']['observations']
        assert observations[0]['value']['witness'] is False
        assert observations[1]['value']['witness'] is True
        assert assess_observations(observations,'cleared' if side=='flagged' else 'flagged')=='behaviour_mismatch'


def test_upstream_snapshot_hashes_and_exact_regex_extraction():
    for source in SOURCES:assert file_hash(Path(source['path']))==source['sha256']
    text,_=load_context('undici')
    code=extract(text,['headerCharRegex'])
    assert code in text
    assert r'\x20-\x7e' in code
    with pytest.raises(ValueError,match='Missing exact helper'):
        extract(text,['notARealHelper'])


def test_matching_helper_source_cannot_be_reused_at_another_fix():
    entry=next(e for e in TARGETS if e.advisory.package_name=='moment').model_copy(deep=True)
    entry.origin.fix_commit_sha='0'*40
    with pytest.raises(ValueError,match='exact reference'):
        load_context('moment',entry)


def test_fastify_requires_matching_constructor_and_consumers():
    entry=next(e for e in TARGETS if e.origin.function_name=='ContentTypeParser')
    incomplete=[e for e in ENTRIES if e.origin.function_name!='ContentTypeParser.prototype.getParser']
    result=check(dict(candidate_source=entry.patched_function,expected_status='cleared'),entry,incomplete)
    assert result['status']=='inconclusive_execution_or_context'
    assert 'matching Fastify context' in result['error']


def test_local_callee_rename_does_not_create_a_behaviour_failure():
    import re
    entry=next(e for e in TARGETS if e.advisory.package_name=='axios')
    source=re.sub(r'\bmerge\b','merger',entry.vulnerable_function)
    result=check(dict(candidate_source=source,expected_status='flagged'),entry,ENTRIES)
    assert result['status']=='pass',result
    assert comparison_view({'name':'Error','error':'merge is not a function'})['error']=='merge is not a function'
    assert comparison_view({'name':'TypeError','error':'obj.merge is not a function'})['error']=='obj.merge is not a function'


@pytest.mark.parametrize('candidate_id,status',[
    ('L257','behaviour_mismatch'),('L261','behaviour_mismatch'),('LN269','behaviour_mismatch'),
    ('T2-322874b74df4a3286af2','candidate_compile_error'),
    ('T2-db520c0757f66e2ed6db','behaviour_mismatch'),
])
def test_real_candidate_defects_after_entrypoint_adaptation(candidate_id,status):
    record=next(r for r in build_records(ENTRIES) if r['candidate_id']==candidate_id)
    from eval.ablation.common import entry_identity
    entry=next(e for e in ENTRIES if entry_identity(e)==identity(record))
    result=check(record,entry,ENTRIES)
    assert result['status']==status,result
    if candidate_id=='L257':
        assert result['callable_adapters'][2]['name']=='rewrite'
        assert callable_adapter(record['candidate_source']+'\n','typescript','L257') is None


def test_ambiguous_valid_program_is_inconclusive_not_invalid():
    entry=next(e for e in TARGETS if e.advisory.package_name=='vite')
    source='const a=()=>1; const b=()=>2;'
    result=check(dict(candidate_source=source,expected_status='cleared'),entry,ENTRIES)
    assert result['status']=='inconclusive_candidate_adapter',result
    assert result['execution']['observations'][2]['phase']=='adapter'
