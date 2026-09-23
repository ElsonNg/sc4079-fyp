"""Check Tier 2 pair eligibility against the admitted cohort."""
from collections import Counter
import hashlib
import json

from eval.tier2.recalculate_admitted_pairs import OUTPUT, calculate


def test_pair_recalculation_matches_sealed_report():
    rows = calculate()
    assert len(rows) == 433
    assert sum(r['eligible'] for r in rows) == 167
    assert sum(r['eligible_in_v43'] for r in rows) == 158
    assert sum(r['newly_eligible'] for r in rows) == 9
    assert Counter(r['requested_clone_type'] for r in rows if r['eligible']) == {'type_3': 100, 'type_4': 67}
    assert rows == [json.loads(line) for line in (OUTPUT / 'groups.jsonl').read_text(encoding='utf8').splitlines()]
    lock = json.loads((OUTPUT / 'lock.json').read_text(encoding='utf8'))
    for name in ('groups.jsonl', 'summary.json', 'README.md'):
        assert hashlib.sha256((OUTPUT / name).read_bytes()).hexdigest() == lock[name]
