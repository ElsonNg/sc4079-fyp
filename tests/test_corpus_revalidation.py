"""Behavioural and admission regressions for the separate revalidation pass."""
import copy
from collections import Counter

import pytest

from eval.ablation.common import digest, entry_identity, read_jsonl
from eval.common import DEFAULT_SNAPSHOT_DB
from eval.tier2.adjudicate import origin_key
from eval.tier2.revalidate import assess, executable, outcome, pair_eligibility
from provtrail.corpus.integrations.sqlite_store import load_entries


@pytest.fixture(scope='module')
def entries():
    return load_entries(DEFAULT_SNAPSHOT_DB)


@pytest.fixture(scope='module')
def candidates():
    return {r['candidate_id']: r for name in ('accepted', 'quarantine')
        for r in read_jsonl(f'eval/frozen/tier2-v2/{name}.jsonl')}


def record(entry, side='flagged'):
    source = entry.vulnerable_function if side == 'flagged' else entry.patched_function
    return dict(candidate_id='fixture', tier='tier1', package_name=entry.advisory.package_name,
        source_language=entry.origin.source_language, expected_status=side, candidate_source=source,
        candidate_source_sha256=digest(source), vulnerable_function=entry.vulnerable_function,
        patched_function=entry.patched_function, vulnerable_source_sha256=digest(entry.vulnerable_function),
        patched_source_sha256=digest(entry.patched_function), corpus_entry=dict(zip(
            ('ghsa_id','fix_commit_sha','file_path','function_name'),entry_identity(entry))))


@pytest.mark.parametrize('package,function,fix', [
    ('qs','parseObject',None), ('lodash','safeGet',None),
    ('minimist','isConstructorOrProto',None), ('semver','parse',None),
    ('moment','preprocessRFC2822',None), ('undici','shouldRemoveHeader',None),
    ('next','deleteLength',None), ('nuxt','encodeURL',None),
    ('axios','beforeRedirect',None), ('minimist','setKey','34e20b84'),
    ('nodemailer','_handleAddress','1150d99'), ('parse-server','verifyIdToken',None),
])
def test_each_harness_distinguishes_real_originals_and_accepts_both_sides(entries, package, function, fix):
    e = next(e for e in entries if e.advisory.package_name == package and e.origin.function_name == function
        and (fix is None or e.origin.fix_commit_sha.startswith(fix)))
    for side in ('flagged', 'cleared'):
        result = executable(record(e, side), e, entries)
        assert result['status'] == 'pass', result


@pytest.mark.parametrize('case', ['L014','L080','L081','LN037','T2-73495ca822ef4528f3cc','T2-3681b7202e1150c0ae4f'])
def test_known_transform_defects_fail_actual_execution(entries, candidates, case):
    r = candidates[case]
    e = next(e for e in entries if entry_identity(e) == tuple(r['corpus_entry'][k] for k in
        ('ghsa_id','fix_commit_sha','file_path','function_name')))
    assert executable(r,e,entries)['status'] == 'behaviour_mismatch'


def test_runtime_duplicate_declaration_is_not_a_harness_context_failure(entries, candidates):
    r=candidates['LN042']
    e=next(e for e in entries if entry_identity(e)==tuple(r['corpus_entry'][k] for k in
        ('ghsa_id','fix_commit_sha','file_path','function_name')))
    assert executable(r,e,entries)['status']=='candidate_compile_error'


def test_nondistinguishing_and_missing_reference_context_are_inconclusive():
    ok=lambda value:dict(ok=True,value=value)
    assert outcome([ok(1),ok(1),ok(2)],'flagged')=='inconclusive_non_distinguishing_test'
    assert outcome([dict(ok=False),ok(1),ok(1)],'cleared')=='inconclusive_reference_execution'
    assert outcome([ok(1),ok(2),ok(1)],'cleared')=='behaviour_mismatch'


def test_individual_validation_does_not_imply_pair_or_duplicate_eligibility(candidates):
    records=[copy.deepcopy(candidates['L013'])]
    records[0]['clone_type']='type_3'; records[0]['requested_clone_type']='type_3'
    reviews=[dict(candidate_id='L013',status='validated_executable',confirmed_clone_type='unconfirmed')]
    assert pair_eligibility(records,reviews)==[]
    assert reviews[0]['status']=='validated_executable'
    assert not reviews[0]['pair_complete']
    second=copy.deepcopy(records[0]);second.update(candidate_id='pair',expected_status='cleared')
    records.append(second); reviews.append(dict(candidate_id='pair',status='validated_executable',confirmed_clone_type='unconfirmed'))
    assert pair_eligibility(records,reviews)==[]
    assert reviews[0]['pair_complete']
    assert reviews[0]['duplicate_source_count']==2


def test_source_review_cannot_be_reused_for_changed_reference(entries):
    e=next(e for e in entries if e.advisory.package_name=='vite')
    r=record(e)
    decisions={origin_key(r):dict(origin=list(entry_identity(e)),vulnerable_source_sha256='wrong',patched_source_sha256=digest(e.patched_function))}
    with pytest.raises(ValueError,match='identity mismatch'):
        assess(r,e,entries,decisions,{entry_identity(e):e.model_dump()}, {})


def test_bounded_pass_does_not_override_prior_bound_defect(entries):
    e=next(e for e in entries if e.advisory.package_name=='next' and e.origin.function_name=='deleteLength')
    r=record(e); r['tier']='tier2'
    decision=dict(origin_key=origin_key(r),origin=list(entry_identity(e)),
        vulnerable_source_sha256=digest(e.vulnerable_function),patched_source_sha256=digest(e.patched_function),
        vulnerable_quote=e.vulnerable_function,patched_quote=e.patched_function,supported=True,
        candidate_reviews=[dict(candidate_id='fixture',candidate_sha256=digest(r['candidate_source']),accepted=False,
            preservation_reason='Previously identified out-of-harness defect requires review')])
    result=assess(r,e,entries,{origin_key(r):decision},{entry_identity(e):e.model_dump()}, {})
    assert result['executable_evidence']['status']=='pass'
    assert result['status']=='needs_review'


def test_identity_mismatch_is_not_behaviour_failure(entries):
    e=entries[0];r=record(e);r['candidate_source_sha256']='wrong'
    result=assess(r,e,entries,{}, {}, {})
    assert result['status']=='source_or_parse_mismatch'
    assert 'candidate_source_identity_mismatch' in result['reasons']
