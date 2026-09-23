"""Add 80 complete, statically proven Type 2 local-renaming pairs."""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

from eval.ablation.common import digest, entry_identity, source_key
from eval.common import DEFAULT_SNAPSHOT_DB
from eval.tier2.alpha_expansion_probe import candidates
from eval.tier2.extend_validation_v3 import build_records, read_jsonl
from eval.tier2.generate_llm_transformed_subset import _base_record
from eval.tier2.static_preservation import compare_shorthand_aliases
from provtrail.corpus.integrations.sqlite_store import load_entries

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / 'eval/frozen/tier2-alpha-expansion-v1'
PAIR_REPORT = ROOT / 'eval/frozen/tier2-pairs-after-admission-v1/groups.jsonl'
ADMISSION = ROOT / 'eval/frozen/tier2-candidate-admission-v1/cases.jsonl'
PAIR_TARGET = 80


def select():
    eligible_origins = {tuple(r['origin']) for r in read_jsonl(PAIR_REPORT) if r['eligible']}
    options = candidates()
    buckets = defaultdict(list)
    used = set()
    for option in options:
        entry = option[0]
        origin = entry_identity(entry)
        if origin in eligible_origins or origin in used:
            continue
        used.add(origin)
        buckets[entry.advisory.package_name].append(option)
    for package in buckets:
        buckets[package].sort(key=lambda option: str(entry_identity(option[0])))
    selected = []
    while len(selected) < PAIR_TARGET and any(buckets.values()):
        for package in sorted(buckets):
            if buckets[package] and len(selected) < PAIR_TARGET:
                selected.append(buckets[package].pop(0))
    assert len(selected) == PAIR_TARGET and len({entry_identity(x[0]) for x in selected}) == PAIR_TARGET
    return selected


def build():
    selected = select()
    records, reviews, pair_rows = [], [], []
    existing = read_jsonl(ADMISSION)
    assert sum(r['disposition'].startswith('admitted_') for r in existing) == 442
    seen = set()
    for entry, old, new, transformed, earlier_reviews, keys in selected:
        origin = entry_identity(entry)
        ids = {}
        for side, candidate, proof, key in zip(('vulnerable', 'patched'), transformed, earlier_reviews, keys):
            source = getattr(entry, side + '_function')
            assert old != new and old in source and new not in source
            assert proof['preserved']
            assert compare_shorthand_aliases(source, candidate, entry.origin.source_language)['preserved']
            assert key not in seen
            seen.add(key)
            cid = 'A2-' + digest([origin, old, new, side])[:20]
            ids[side] = cid
            record = _base_record(entry, candidate, 'type_2')
            record.update(candidate_id=cid, expected_status='flagged' if side == 'vulnerable' else 'cleared',
                          generation_method='deterministic_local_binding_rename',
                          transformation_family='alpha_local_binding_rename',
                          requested_clone_type='type_2', confirmed_clone_type='type_2',
                          clone_type_status='verified', tier='tier2',
                          generator={'name': 'static-tree-sitter-rename', 'model': None},
                          rename={'from': old, 'to': new})
            records.append(record)
            reviews.append({'candidate_id': cid, 'admitted': True, 'confirmed_clone_type': 'type_2',
                            'expected_status': record['expected_status'], 'origin': list(origin),
                            'source_sha256': digest(source), 'candidate_sha256': digest(candidate),
                            'source_key': key, 'proof': proof,
                            'source_advisory_verdict': 'valid_advisory_reference',
                            'method': 'Complete declared-language syntax-tree comparison under a unique, capture-free top-level local-binding rename; no exploit execution.'})
        pair_rows.append({'origin': list(origin), 'package': entry.advisory.package_name,
                          'requested_clone_type': 'type_2', 'candidate_ids': ids,
                          'eligible': True, 'source_unique': True})
    assert len(records) == len(reviews) == 160 and len(pair_rows) == 80
    return records, reviews, pair_rows


def main():
    records, reviews, pairs = build()
    admitted = {r['candidate_id'] for r in read_jsonl(ADMISSION)
                if r['disposition'].startswith('admitted_')}
    old_records = [r for r in build_records(load_entries(DEFAULT_SNAPSHOT_DB))
                   if r['tier'] == 'tier2' and r['candidate_id'] in admitted]
    assert len(old_records) == 442
    combined = old_records + records
    assert len(combined) == len({r['candidate_id'] for r in combined}) == 602
    old_pairs = [r for r in read_jsonl(PAIR_REPORT) if r['eligible']]
    combined_pairs = [{'origin': r['origin'], 'package': r['package'],
                       'requested_clone_type': r['requested_clone_type'],
                       'candidate_ids': r['candidate_ids'], 'cohort': 'original_tier2'} for r in old_pairs]
    combined_pairs += [{'origin': r['origin'], 'package': r['package'],
                        'requested_clone_type': 'type_2',
                        'candidate_ids': {'flagged': r['candidate_ids']['vulnerable'],
                                          'cleared': r['candidate_ids']['patched']},
                        'cohort': 'alpha_expansion_v1'} for r in pairs]
    assert len(combined_pairs) == 247
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for name, rows in (('records.jsonl', records), ('validation.jsonl', reviews),
                       ('pairs.jsonl', pairs), ('combined_admitted.jsonl', combined),
                       ('combined_eligible_pairs.jsonl', combined_pairs)):
        (OUTPUT / name).write_text(''.join(json.dumps(row, ensure_ascii=False) + '\n' for row in rows), encoding='utf8')
    package_counts = Counter(row['package'] for row in pairs)
    summary = {'new_pairs': 80, 'new_verified_tier2_cases': 160,
               'previous_verified_tier2_cases': 442, 'combined_verified_tier2_cases': 602,
               'previous_eligible_pairs': 167, 'combined_eligible_pairs': 247,
               'combined_eligible_cases': 494,
               'confirmed_clone_type': 'type_2', 'new_pairs_by_package': dict(package_counts),
               'method': 'Deterministic unique top-level local-binding renames with full-tree static preservation proof; no exploit execution.'}
    (OUTPUT / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf8')
    readme = ['# Tier 2 Type 2 expansion', '',
              'This versioned cohort adds 160 verified Type 2 candidates in 80 complete vulnerable/patched pairs. Each changes one unique top-level local binding in the advisory-valid fix-commit reference. The declared-language syntax trees match under the recorded rename, and every new source key is distinct from the existing 788 Tier 2 cases and from every other new case.', '',
              'Combined with the 442 previously admitted Tier 2 cases, the verified count is **602**. Applying the existing complete-pair and unique-source rule yields **247 eligible pairs (494 cases)**. The expansion consists of mechanically verified identifier-renaming clones; it does not increase the number of Type 3/4 rewrites or establish exploitability.', '',
              'The original 788-case pool, v43 run, and prior admission decision remain unchanged. `records.jsonl`, `validation.jsonl`, and `pairs.jsonl` make the expansion reviewable. `combined_admitted.jsonl` is the complete 602-case usable Tier 2 cohort, and `combined_eligible_pairs.jsonl` lists its 247 eligible pairs.', '']
    (OUTPUT / 'README.md').write_text('\n'.join(readme), encoding='utf8')
    names = ('records.jsonl', 'validation.jsonl', 'pairs.jsonl', 'combined_admitted.jsonl',
             'combined_eligible_pairs.jsonl', 'summary.json', 'README.md')
    lock = {name: hashlib.sha256((OUTPUT / name).read_bytes()).hexdigest() for name in names}
    lock['inputs'] = {str(path.relative_to(ROOT)).replace('\\', '/'): hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in (PAIR_REPORT, ADMISSION, Path(__file__),
                                   Path(__file__).with_name('alpha_expansion_probe.py'),
                                   Path(__file__).with_name('static_preservation.py'), DEFAULT_SNAPSHOT_DB)}
    (OUTPUT / 'lock.json').write_text(json.dumps(lock, indent=2) + '\n', encoding='utf8')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
