import pytest
from eval.common import DEFAULT_SNAPSHOT_DB
from eval.tier2.header_checks import check,selected
from eval.tier2.batch_support import snapshot,SOURCES
from eval.tier2.additional_checks import assess_observations
from provtrail.corpus.integrations.sqlite_store import load_entries
ENTRIES=load_entries(DEFAULT_SNAPSHOT_DB)
TARGETS=[e for e in ENTRIES if selected(e)]

@pytest.mark.parametrize('entry',TARGETS,ids=lambda e:f'{e.advisory.package_name}-{e.origin.function_name}-{e.origin.fix_commit_sha[:8]}')
def test_originals_and_wrong_label(entry):
    for side,source in [('flagged',entry.vulnerable_function),('cleared',entry.patched_function)]:
        result=check(dict(candidate_source=source,expected_status=side),entry,ENTRIES)
        assert result['status']=='pass',result
        obs=result['execution']['observations']
        assert obs[0]['value']['witness'] is False and obs[1]['value']['witness'] is True
        assert assess_observations(obs,'cleared' if side=='flagged' else 'flagged')=='behaviour_mismatch'

def test_always_rejecting_cookie_domain_is_not_equivalent():
    entry=next(e for e in TARGETS if e.origin.function_name=='validateCookieDomain')
    result=check(dict(candidate_source="function(){throw new Error('Invalid cookie domain');}",expected_status='cleared'),entry,ENTRIES)
    assert result['execution']['observations'][2]['value']['witness'] is True
    assert result['status']=='behaviour_mismatch'

def test_cookie_helpers_are_bound_to_exact_fix(monkeypatch):
    entry=next(e for e in TARGETS if e.origin.function_name=='stringify')
    record=next(r for r in SOURCES if r['commit']==entry.origin.fix_commit_sha and r['file']==entry.origin.file_path)
    monkeypatch.setitem(record,'sha256','0'*64)
    result=check(dict(candidate_source=entry.patched_function,expected_status='cleared'),entry,ENTRIES)
    assert result['status']=='inconclusive_execution_or_context'

def test_helper_snapshot_cannot_be_taken_from_another_fix():
    entry=next(e for e in TARGETS if e.advisory.package_name=='axios').model_copy(deep=True)
    entry.origin.fix_commit_sha='0'*40
    with pytest.raises(StopIteration):snapshot(entry,'lib/helpers/shouldBypassProxy.js')

def test_unicode_cookie_observations_survive_windows_transport():
    entry=next(e for e in TARGETS if e.origin.function_name=='stringify')
    result=check(dict(candidate_source=entry.vulnerable_function,expected_status='flagged'),entry,ENTRIES)
    assert result['status']=='pass'
    controls=result['execution']['observations'][2]['value']['controls']
    assert any(c['cookie']['unparsed']==['x=a\x81b'] and c['result']['value'].endswith('x=a\x81b') for c in controls)

def test_redirect_strips_stale_headers_but_preserves_initial_user_headers():
    entry=next(e for e in TARGETS if e.advisory.package_name=='axios' and 'isRedirect' in e.patched_function)
    result=check(dict(candidate_source=entry.patched_function,expected_status='cleared'),entry,ENTRIES)
    value=result['execution']['observations'][2]['value']
    assert value['witness'] is True
    assert value['controls'][1]['initial']['headers']['Proxy-Authorization']=='stale-upper'
    assert value['controls'][1]['initial']['headers']['pRoXy-AuThOrIzAtIoN']=='stale-mixed'
    assert all(k.lower()!='proxy-authorization' for k in value['boundary']['redirect']['options']['headers'])
    assert value['boundary']['redirect']['options']['headers']['ordinary']=='keep'
