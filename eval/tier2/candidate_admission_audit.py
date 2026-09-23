"""Conservative final Tier 2 candidate admission, separate from sealed v43."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path

from eval.tier2.extend_validation_v3 import read_jsonl
from eval.tier2.transformation_static_audit_v2 import ROOT, OUTPUT as STATIC_OUTPUT

SOURCE = ROOT / 'eval/frozen/tier2-advisory-audit-v1/cases.jsonl'
PREVIOUS = ROOT / 'eval/frozen/revalidation-v43/validation.jsonl'
OUTPUT = ROOT / 'eval/frozen/tier2-candidate-admission-v1'


def audit():
    sources = read_jsonl(SOURCE)
    previous = {r['candidate_id']: r for r in read_jsonl(PREVIOUS) if r['tier'] == 'tier2'}
    static = {r['candidate_id']: r for r in read_jsonl(STATIC_OUTPUT / 'cases.jsonl')}
    assert len(sources) == len(previous) == 788 and len(static) == 234
    rows = []
    for source in sources:
        cid = source['candidate_id']
        old = previous[cid]
        review = static.get(cid)
        if source['advisory_source_verdict'] == 'excluded_non_security_source':
            disposition = 'excluded_source_label'
            reason = 'The Tier 1 advisory/source audit does not support this extracted function as a security-labelled source.'
        elif old['status'].startswith('validated_'):
            disposition = 'admitted_v43'
            reason = old['status']
        elif old['status'] in {'failed_behaviour', 'failed_runtime_parse'}:
            disposition = 'rejected_v43_failure'
            reason = old['reasons'][0]
        elif review and review['verdict'].startswith('verified_'):
            disposition = 'admitted_static_preservation'
            reason = review['basis']
        elif review and review['verdict'] == 'changed':
            disposition = 'rejected_changed_source'
            reason = review['basis']
        elif review and review['verdict'] == 'not_verified_prior_review':
            disposition = 'excluded_prior_negative_review'
            reason = review['basis']
        elif review and review['verdict'] == 'not_verified_structural':
            disposition = 'excluded_insufficient_preservation_evidence'
            reason = review['normalized_tree_comparison']['reason']
        else:
            raise AssertionError(f'Unclassified Tier 2 case: {cid}')
        rows.append({'candidate_id': cid, 'disposition': disposition, 'reason': reason,
                     'advisory_source_verdict': source['advisory_source_verdict'],
                     'previous_v43_status': old['status'],
                     'static_review_verdict': review['verdict'] if review else None,
                     'origin': source['origin'], 'candidate_sha256': source['candidate_sha256'],
                     'source_sha256': source['declared_reference_sha256'],
                     'limitation': 'Admission is conservative: exclusion for insufficient evidence is not a finding that the rewrite is invalid.'})
    return rows


def main():
    rows = audit()
    counts = Counter(r['disposition'] for r in rows)
    assert counts == {'admitted_v43': 388, 'admitted_static_preservation': 54,
                      'rejected_v43_failure': 88, 'excluded_source_label': 78,
                      'rejected_changed_source': 14, 'excluded_prior_negative_review': 5,
                      'excluded_insufficient_preservation_evidence': 161}, counts
    summary = {'total': 788, 'dispositions': dict(counts),
               'admitted_candidates': counts['admitted_v43'] + counts['admitted_static_preservation'],
               'not_admitted_candidates': 788 - counts['admitted_v43'] - counts['admitted_static_preservation'],
               'undecided_for_admission': 0,
               'source_validity_complete': True,
               'unverified_transformations_excluded_not_proven_invalid': counts['excluded_insufficient_preservation_evidence'],
               'v43_pair_eligibility_recomputed': False,
               'scope': 'Static/source-supported candidate admission; no exploitability inference or new exploit execution.'}
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / 'cases.jsonl').write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows), encoding='utf8')
    (OUTPUT / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf8')
    readme = ['# Tier 2 candidate admission decision', '',
              'All 788 Tier 2 records have a case-level conservative admission decision. 442 are admitted: 388 retain v43 support and 54 gain static source-preservation evidence. The other 346 are not admitted: 88 failed prior recorded checks, 78 have excluded advisory/source labels, 14 have concrete source changes, five have earlier negative preservation reviews, and 161 have insufficient evidence for a generated-code preservation claim.', '',
              'The 161 insufficient-evidence cases are **not** called invalid. They are withheld from the trusted candidate subset because structural edits remain unverified. Their complete source-to-candidate line diffs and static reasons are in the [v2 transformation audit](../tier2-transformation-static-audit-v2/README.md).', '',
              'No exploit inputs were run. This decision does not alter v43 or recalculate pairing/clone-category eligibility.', '']
    (OUTPUT / 'README.md').write_text('\n'.join(readme), encoding='utf8')
    lock = {name: hashlib.sha256((OUTPUT / name).read_bytes()).hexdigest()
            for name in ('cases.jsonl', 'summary.json', 'README.md')}
    lock['inputs'] = {str(path.relative_to(ROOT)).replace('\\', '/'): hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in (SOURCE, PREVIOUS, STATIC_OUTPUT / 'cases.jsonl', Path(__file__))}
    (OUTPUT / 'lock.json').write_text(json.dumps(lock, indent=2) + '\n', encoding='utf8')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
