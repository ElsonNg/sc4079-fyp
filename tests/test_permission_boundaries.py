from pathlib import Path
import pytest
from eval.ablation.common import ROOT,file_hash
from eval.common import DEFAULT_SNAPSHOT_DB
from eval.tier2.permission_checks import check,selected,helper_context,SOURCES
from eval.tier2.permission_checks import observation_view
from eval.tier2.extend_validation import build_records
from eval.ablation.common import entry_identity,identity
from eval.tier2.additional_checks import assess_observations
from provtrail.corpus.integrations.sqlite_store import load_entries

ENTRIES=load_entries(DEFAULT_SNAPSHOT_DB)
TARGETS=[e for e in ENTRIES if selected(e)]


@pytest.mark.parametrize('entry',TARGETS,ids=lambda e:f'{e.advisory.package_name}-{e.origin.function_name}-{e.origin.fix_commit_sha[:8]}')
def test_originals_distinguish_security_boundary_and_wrong_label(entry):
    for side,source in [('flagged',entry.vulnerable_function),('cleared',entry.patched_function)]:
        result=check(dict(candidate_source=source,expected_status=side),entry,ENTRIES)
        assert result['status']=='pass',result
        observations=result['execution']['observations']
        assert observations[0]['value']['witness'] is False
        assert observations[1]['value']['witness'] is True
        assert assess_observations(observations,'cleared' if side=='flagged' else 'flagged')=='behaviour_mismatch'


def test_helper_snapshots_and_exact_fix_binding():
    for r in SOURCES:assert file_hash(ROOT/r['path'])==r['sha256']
    entry=next(e for e in TARGETS if e.advisory.package_name=='minimist').model_copy(deep=True)
    code,proof=helper_context(entry)
    assert "key === 'constructor'" in code
    assert proof[0]['commit']==entry.origin.fix_commit_sha
    entry.origin.fix_commit_sha='0'*40
    with pytest.raises(StopIteration):helper_context(entry)


def test_ambiguous_entry_stays_inconclusive():
    entry=next(e for e in TARGETS if e.advisory.package_name=='vite')
    result=check(dict(candidate_source='const a=()=>1; const b=()=>2;',expected_status='cleared'),entry,ENTRIES)
    assert result['status']=='inconclusive_candidate_adapter'


@pytest.mark.parametrize('candidate_id,status',[
    ('L139','pass'),('L159','pass'),('L099','behaviour_mismatch'),('L105','behaviour_mismatch'),
    ('L168','behaviour_mismatch'),('LN174','behaviour_mismatch'),('L277','behaviour_mismatch'),
])
def test_transforms_distinguish_real_defects_from_engine_rename_messages(candidate_id,status):
    record=next(r for r in build_records(ENTRIES) if r['candidate_id']==candidate_id)
    entry=next(e for e in TARGETS if entry_identity(e)==identity(record))
    result=check(record,entry,ENTRIES)
    assert result['status']==status,result


def test_error_normalization_preserves_property_type_and_state():
    view=lambda message,name='TypeError':observation_view(dict(error=message,name=name))
    assert view('header.split is not a function')==view('renamed.split is not a function')
    assert view('header.split is not a function')!=view('renamed.trim is not a function')
    assert view('header.split is not a function','Error')!=view('renamed.split is not a function','Error')
    a="Cannot destructure property 'filesController' of 'config' as it is undefined."
    b=a.replace("'config'","'renamed'")
    assert view(a)==view(b)
    assert view(a)!=view(b.replace('undefined','null'))
    assert view(a)!=view(b.replace('filesController','controller'))


def test_helper_hash_mismatch_is_inconclusive(monkeypatch):
    entry=next(e for e in TARGETS if e.advisory.package_name=='minimist')
    record=next(r for r in SOURCES if r['package']=='minimist' and r['file']=='index.js')
    monkeypatch.setitem(record,'sha256','0'*64)
    result=check(dict(candidate_source=entry.patched_function,expected_status='cleared'),entry,ENTRIES)
    assert result['status']=='inconclusive_execution_or_context'
    assert 'hash mismatch' in result['error']
