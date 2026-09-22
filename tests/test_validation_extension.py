import json
import subprocess

import pytest

from eval.ablation.common import file_hash,seal,write_json
from eval.tier2.extend_validation import summarize,validate_checkpoint,verify_previous


def make_previous(tmp_path):
    source=tmp_path/'original.txt';source.write_text('original source')
    output=tmp_path/'validation.jsonl';output.write_text('{}\n')
    write_json(tmp_path/'lock.json',seal(dict(inputs={str(source):file_hash(source)},dependencies={},
        node=subprocess.check_output(['node','--version'],text=True).strip())))
    write_json(tmp_path/'output-lock.json',seal(dict(run_lock_sha256=file_hash(tmp_path/'lock.json'),outputs={'validation.jsonl':file_hash(output)})))
    return tmp_path


def test_inherited_evidence_must_match_original_output_hash(tmp_path):
    previous=make_previous(tmp_path)
    verify_previous(previous)
    (previous/'validation.jsonl').write_text('{"accepted":true}\n')
    with pytest.raises(ValueError,match='Previous output mismatch'):
        verify_previous(previous)


def test_inherited_evidence_must_match_original_source_and_code(tmp_path):
    previous=make_previous(tmp_path)
    (previous/'original.txt').write_text('different source')
    with pytest.raises(ValueError,match='Previous input/code mismatch'):
        verify_previous(previous)


def test_checkpoints_bind_candidate_configuration_and_evidence():
    item=seal(dict(candidate_id='A',key='config-and-source',result={'status':'validated_executable'}))
    assert validate_checkpoint(item,'config-and-source','A')['status']=='validated_executable'
    for key,candidate in [('wrong','A'),('config-and-source','B')]:
        with pytest.raises(ValueError,match='Checkpoint candidate/configuration mismatch'):
            validate_checkpoint(item,key,candidate)


def test_metrics_partition_all_cases_and_do_not_count_review_upgrades_as_new_cases():
    previous={}
    rows=[]
    for i,(tier,before,after) in enumerate([
        ('tier1','needs_review','validated_executable'),
        ('tier1','validated_source_review','validated_executable'),
        ('tier1','needs_review','needs_review'),
        ('tier2','needs_review','failed_behaviour'),
        ('tier2','needs_review','validated_executable'),
        ('tier2','source_or_parse_mismatch','source_or_parse_mismatch'),
    ]):
        previous[str(i)]=dict(status=before)
        rows.append(dict(candidate_id=str(i),tier=tier,package_name='package',status=after))
    summary,changes=summarize(rows,[],previous)
    assert summary['tier1']['total']==summary['tier2']['total']==3
    assert summary['tier1']['validated']==2
    assert summary['tier2']['validated']==1
    assert sum(summary['tier1']['statuses'].values())==3
    assert sum(summary['tier2']['statuses'].values())==3
    assert sum(r['status'].startswith('validated_') and not previous[r['candidate_id']]['status'].startswith('validated_') for r in changes)==2
