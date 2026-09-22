import json
import pytest
from eval.ablation.common import write_jsonl
from eval.tier2.extend_validation_v2 import read_jsonl

def test_raw_unicode_line_separators_are_data_not_record_boundaries(tmp_path):
    path=tmp_path/'cases.jsonl'
    rows=[dict(candidate_id='one',source='a\x85b\u2028c\u2029d'),dict(candidate_id='two',source='ordinary')]
    write_jsonl(path,rows)
    assert '\x85' in path.read_text(encoding='utf-8')
    assert read_jsonl(path)==rows

def test_crlf_records_and_escaped_newlines_remain_supported(tmp_path):
    path=tmp_path/'cases.jsonl'
    path.write_bytes((json.dumps({'text':'a\nb'})+'\r\n\r\n'+json.dumps({'text':'c'})+'\r\n').encode())
    assert read_jsonl(path)==[{'text':'a\nb'},{'text':'c'}]

def test_literal_lf_inside_json_string_is_rejected(tmp_path):
    path=tmp_path/'cases.jsonl';path.write_text('{"text":"a\nb"}\n',encoding='utf-8')
    with pytest.raises(json.JSONDecodeError):read_jsonl(path)
