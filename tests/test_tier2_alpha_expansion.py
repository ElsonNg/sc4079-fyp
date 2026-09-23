"""Verify the 80 new Type 2 pairs against the frozen corpus and pair rules."""
from collections import Counter
import hashlib
import json

from eval.ablation.common import entry_identity, identity, source_key
from eval.common import DEFAULT_SNAPSHOT_DB
from eval.tier2.build_alpha_expansion import OUTPUT, build
from eval.tier2.cohort import screen
from eval.tier2.extend_validation_v3 import build_records, read_jsonl
from eval.tier2.revalidate import pair_eligibility
from eval.tier2.static_preservation import compare_shorthand_aliases
from provtrail.corpus.integrations.sqlite_store import load_entries


def test_expansion_has_160_independent_preserved_sources():
    records, reviews, pairs = build()
    assert len(records) == len(reviews) == 160 and len(pairs) == 80
    assert records == read_jsonl(OUTPUT / 'records.jsonl')
    assert reviews == read_jsonl(OUTPUT / 'validation.jsonl')
    assert pairs == read_jsonl(OUTPUT / 'pairs.jsonl')
    assert len(read_jsonl(OUTPUT / 'combined_admitted.jsonl')) == 602
    assert len(read_jsonl(OUTPUT / 'combined_eligible_pairs.jsonl')) == 247
    assert len({r['candidate_id'] for r in records}) == 160
    assert len({tuple(p['origin']) for p in pairs}) == 80
    entries = load_entries(DEFAULT_SNAPSHOT_DB)
    by_origin = {entry_identity(entry): entry for entry in entries}
    previous = [r for r in build_records(entries) if r['tier'] == 'tier2']
    previous_keys = {source_key(r['candidate_source'], r['source_language']) for r in previous}
    new_keys = []
    for record in records:
        entry = by_origin[identity(record)]
        reasons, gate = screen(record, entry)
        assert not reasons and gate['passed'], record['candidate_id']
        side = 'vulnerable' if record['expected_status'] == 'flagged' else 'patched'
        assert compare_shorthand_aliases(getattr(entry, side + '_function'), record['candidate_source'],
                                         record['source_language'])['preserved']
        key = source_key(record['candidate_source'], record['source_language'])
        assert key not in previous_keys
        new_keys.append(key)
    assert len(set(new_keys)) == 160
    lock = json.loads((OUTPUT / 'lock.json').read_text(encoding='utf8'))
    for name in ('records.jsonl', 'validation.jsonl', 'pairs.jsonl',
                 'combined_admitted.jsonl', 'combined_eligible_pairs.jsonl',
                 'summary.json', 'README.md'):
        assert hashlib.sha256((OUTPUT / name).read_bytes()).hexdigest() == lock[name]


def test_combined_pool_has_602_admissions_and_247_pairs():
    entries = load_entries(DEFAULT_SNAPSHOT_DB)
    old = [r for r in build_records(entries) if r['tier'] == 'tier2']
    new = read_jsonl(OUTPUT / 'records.jsonl')
    admitted = {r['candidate_id']: r for r in read_jsonl('eval/frozen/tier2-candidate-admission-v1/cases.jsonl')}
    validation = [dict(candidate_id=r['candidate_id'],
                       status='validated_source_review' if admitted[r['candidate_id']]['disposition'].startswith('admitted_') else 'needs_review',
                       confirmed_clone_type='unconfirmed') for r in old]
    validation += [dict(candidate_id=r['candidate_id'], status='validated_source_review',
                        confirmed_clone_type='type_2') for r in new]
    assert sum(r['status'].startswith('validated_') for r in validation) == 602
    eligible = pair_eligibility(old + new, validation)
    assert len(eligible) == 494
    assert Counter(r['requested_clone_type'] for r in eligible) == {'type_3': 200, 'type_2': 160, 'type_4': 134}
    pair_file = read_jsonl(OUTPUT / 'combined_eligible_pairs.jsonl')
    assert {cid for pair in pair_file for cid in pair['candidate_ids'].values()} == {
        row['candidate_id'] for row in eligible}
