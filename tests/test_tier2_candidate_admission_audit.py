"""Regression checks for conservative Tier 2 candidate admission."""
from collections import Counter
import hashlib
import json

from eval.common import DEFAULT_SNAPSHOT_DB
from eval.tier2.candidate_admission_audit import OUTPUT, audit
from eval.tier2.extend_validation_v3 import build_records, read_jsonl
from eval.tier2.static_preservation import compare_shorthand_aliases
from provtrail.corpus.integrations.sqlite_store import load_entries


def test_complete_tier2_admission_and_hash_lock():
    rows = audit()
    assert len(rows) == len({r['candidate_id'] for r in rows}) == 788
    assert Counter(r['disposition'] for r in rows) == {
        'admitted_v43': 388, 'admitted_static_preservation': 54,
        'rejected_v43_failure': 88, 'excluded_source_label': 78,
        'rejected_changed_source': 14, 'excluded_prior_negative_review': 5,
        'excluded_insufficient_preservation_evidence': 161,
    }
    assert rows == read_jsonl(OUTPUT / 'cases.jsonl')
    lock = json.loads((OUTPUT / 'lock.json').read_text(encoding='utf8'))
    for name in ('cases.jsonl', 'summary.json', 'README.md'):
        assert hashlib.sha256((OUTPUT / name).read_bytes()).hexdigest() == lock[name]


def test_normalized_tree_reviewer_rejects_known_failed_cases():
    records = {r['candidate_id']: r for r in build_records(load_entries(DEFAULT_SNAPSHOT_DB))
               if r['tier'] == 'tier2'}
    failed = [r for r in read_jsonl('eval/frozen/revalidation-v43/validation.jsonl')
              if r['tier'] == 'tier2' and r['status'] in ('failed_behaviour', 'failed_runtime_parse')]
    assert len(failed) == 96
    for row in failed:
        record = records[row['candidate_id']]
        side = 'vulnerable' if record['expected_status'] == 'flagged' else 'patched'
        result = compare_shorthand_aliases(record[side + '_function'], record['candidate_source'], record['source_language'])
        assert not result['preserved'], row['candidate_id']


def test_normalized_tree_reviewer_preserves_property_keys():
    source = 'function read(obj) { const {value} = obj; return {value}; }'
    safe = 'function read(obj) { const {value: item} = obj; return {value: item}; }'
    unsafe = 'function read(obj) { const {other: item} = obj; return {value: item}; }'
    assert compare_shorthand_aliases(source, safe, 'javascript')['preserved']
    assert not compare_shorthand_aliases(source, unsafe, 'javascript')['preserved']
