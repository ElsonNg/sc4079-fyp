"""Recalculate Tier 2 paired eligibility after conservative candidate admission."""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

from eval.ablation.common import identity, source_key
from eval.common import DEFAULT_SNAPSHOT_DB
from eval.tier2.extend_validation_v3 import build_records, read_jsonl
from provtrail.corpus.integrations.sqlite_store import load_entries

ROOT = Path(__file__).resolve().parents[2]
ADMISSION = ROOT / 'eval/frozen/tier2-candidate-admission-v1/cases.jsonl'
PREVIOUS = ROOT / 'eval/frozen/revalidation-v43/validation.jsonl'
OUTPUT = ROOT / 'eval/frozen/tier2-pairs-after-admission-v1'


def calculate():
    records = [r for r in build_records(load_entries(DEFAULT_SNAPSHOT_DB)) if r['tier'] == 'tier2']
    admission = {r['candidate_id']: r for r in read_jsonl(ADMISSION)}
    previous = {r['candidate_id']: r for r in read_jsonl(PREVIOUS) if r['tier'] == 'tier2'}
    assert len(records) == len(admission) == len(previous) == 788
    source_counts = Counter(source_key(r['candidate_source'], r['source_language']) for r in records)
    groups = defaultdict(list)
    for r in records:
        groups[(identity(r), r.get('requested_clone_type', r['clone_type']))].append(r)
    rows = []
    baseline = 0
    for (origin, requested_type), group in sorted(groups.items(), key=lambda x: str(x[0])):
        complete = len(group) == 2 and {r['expected_status'] for r in group} == {'flagged', 'cleared'}
        unique = all(source_counts[source_key(r['candidate_source'], r['source_language'])] == 1 for r in group)
        current_admitted = all(admission[r['candidate_id']]['disposition'].startswith('admitted_') for r in group)
        previous_admitted = all(previous[r['candidate_id']]['status'].startswith('validated_') for r in group)
        current_eligible = complete and unique and current_admitted
        previous_eligible = complete and unique and previous_admitted
        baseline += int(previous_eligible)
        rows.append({'origin': list(origin), 'package': group[0]['package_name'],
                     'requested_clone_type': requested_type,
                     'candidate_ids': {r['expected_status']: r['candidate_id'] for r in group},
                     'candidate_count': len(group), 'complete': complete,
                     'unique_source': unique, 'admitted_both': current_admitted,
                     'eligible': current_eligible, 'eligible_in_v43': previous_eligible,
                     'newly_eligible': current_eligible and not previous_eligible})
    assert baseline == 158
    return rows


def main():
    rows = calculate()
    eligible = [r for r in rows if r['eligible']]
    summary = {'tier2_candidates': 788, 'admitted_candidates': 442,
               'eligible_pairs': len(eligible), 'eligible_candidates': 2 * len(eligible),
               'v43_eligible_pairs': sum(r['eligible_in_v43'] for r in rows),
               'newly_eligible_pairs': sum(r['newly_eligible'] for r in rows),
               'admitted_candidates_not_pair_eligible': 442 - 2 * len(eligible),
               'eligible_pairs_by_requested_type': dict(Counter(r['requested_clone_type'] for r in eligible)),
               'eligible_pairs_by_package': dict(Counter(r['package'] for r in eligible)),
               'rule': 'Exactly one flagged and one cleared candidate per origin/requested clone type; both admitted and syntax-source-unique across all 788 Tier 2 records.'}
    assert (summary['eligible_pairs'], summary['eligible_candidates'],
            summary['newly_eligible_pairs'], summary['admitted_candidates_not_pair_eligible']) == (167, 334, 9, 108)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / 'groups.jsonl').write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows), encoding='utf8')
    (OUTPUT / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf8')
    readme = ['# Tier 2 eligible pairs after admission', '',
              'Applying the v43 pair rules to the 442 admitted Tier 2 candidates yields **167 eligible pairs (334 cases)**. This is nine pairs (18 cases) above the v43 baseline of 158 pairs (316 cases). The other 108 admitted candidates do not currently satisfy complete, unique pairing.', '',
              'The per-origin decisions and reasons are in `groups.jsonl`. Clone categories remain requested labels unless separately confirmed; this calculation does not infer Type 3/4 semantics.', '']
    (OUTPUT / 'README.md').write_text('\n'.join(readme), encoding='utf8')
    lock = {name: hashlib.sha256((OUTPUT / name).read_bytes()).hexdigest()
            for name in ('groups.jsonl', 'summary.json', 'README.md')}
    lock['inputs'] = {str(path.relative_to(ROOT)).replace('\\', '/'): hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in (ADMISSION, PREVIOUS, Path(__file__), DEFAULT_SNAPSHOT_DB)}
    (OUTPUT / 'lock.json').write_text(json.dumps(lock, indent=2) + '\n', encoding='utf8')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
