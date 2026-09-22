"""Finalize provisional reviews with an explicit audit of extracted security deltas.

This second pass can only remove admissions. It never promotes a rejected model
review or failed executable test. Input journals remain unchanged in their version.
"""
from __future__ import annotations

import argparse
from collections import Counter
import copy
import json
from pathlib import Path
import shutil

from eval.ablation.common import digest, entry_identity, file_hash, identity, read_jsonl, seal, write_json, write_jsonl
from eval.common import DEFAULT_SNAPSHOT_DB
from eval.tier2.cohort import admit, PACKAGES
from eval.tier2.source_review import parsed


def origin_key(row):
    return digest([identity(row), row['vulnerable_source_sha256'], row['patched_source_sha256']])


def literals(source, language):
    """Conservative screen, not semantic proof; retain exact regex escapes."""
    result = Counter()
    def walk(node):
        if node.type == 'comment':
            return
        if node.type in {'string', 'regex', 'number', 'true', 'false', 'null', 'string_fragment'}:
            result[(node.type, node.text.decode())] += 1
            return
        for child in node.children:
            walk(child)
    walk(parsed(source, language))
    return result


def finalize(records, validation, decisions, reference_entries=None):
    originals = {v['candidate_id']: v for v in validation}
    if len(originals) != len(validation) or set(originals) != {r['candidate_id'] for r in records}:
        raise ValueError('Validation and fixture identities differ')
    by_origin = {}
    reference_context = {entry_identity(e): e.model_dump() for e in reference_entries or []}
    for decision in decisions:
        key = decision['origin_key']
        if key in by_origin:
            raise ValueError('Duplicate origin adjudication')
        if decision.get('reviewer_type') != 'automated' or not decision.get('reviewer') or not decision.get('reason'):
            raise ValueError('Missing audit reviewer identity/reason')
        by_origin[key] = decision
    reviews = []
    audit_rows = []
    pending_preservation = set()
    for r in records:
        old = originals[r['candidate_id']]
        if old['candidate_sha256'] != digest(r['candidate_source']):
            raise ValueError('Validation candidate hash mismatch')
        review = copy.deepcopy(old['review'])
        review['accepted'] = bool(old['accepted'])
        audit = {'candidate_id': r['candidate_id'], 'candidate_sha256': digest(r['candidate_source']),
                 'origin_key': origin_key(r), 'provisionally_accepted': bool(old['accepted']),
                 'initial_review_key': review['review_key'], 'reasons': []}
        if old['accepted']:
            executable = review.get('method') == 'executable_security_litmus'
            if executable:
                audit['original_delta_review'] = {'method': 'distinguishing_executable_security_litmus',
                    'evidence': review['executable_security_evidence']}
            else:
                decision = by_origin.get(origin_key(r))
                if decision is None:
                    raise ValueError('Missing explicit source-delta audit: ' + r['candidate_id'])
                for context in decision.get('supporting_reference_context', []):
                    if identity(context)[1] != identity(r)[1] or reference_context.get(identity(context)) != context:
                        raise ValueError('Supporting helper context is not bound to the matching reference fix')
                for field, source in [('vulnerable_quote', r['vulnerable_function']), ('patched_quote', r['patched_function'])]:
                    if not decision.get(field) or decision[field] not in source:
                        raise ValueError('Audit quotation/source mismatch: ' + r['candidate_id'])
                audit['original_delta_review'] = decision
                if decision.get('supported') is not True:
                    audit['reasons'].append('security_delta_not_supported_in_extracted_context')
                source = r['vulnerable_function'] if r['expected_status'] == 'flagged' else r['patched_function']
                same_literals = literals(source, r['source_language']) == literals(r['candidate_source'], r['source_language'])
                audit['literal_screen'] = {'unchanged': same_literals,
                    'scope': 'Conservative screen supplementary to the recorded source-and-patch preservation review; not behavioural proof.'}
                if not same_literals:
                    audit['reasons'].append('changed_literal_or_regex_requires_further_behaviour_evidence')
                if not audit['reasons']:
                    candidate_review = next((c for c in decision.get('candidate_reviews', [])
                        if c['candidate_id'] == r['candidate_id'] and c['candidate_sha256'] == digest(r['candidate_source'])), None)
                    if candidate_review is None or not candidate_review.get('preservation_reason'):
                        pending_preservation.add(r['candidate_id'])
                        audit['reasons'].append('missing_candidate_preservation_audit')
                    else:
                        audit['candidate_preservation_review'] = candidate_review
                    if candidate_review is not None and candidate_review.get('accepted') is not True:
                        audit['reasons'].append('independent_candidate_preservation_review_failed')
            # A model's proposed clone label is not automatically a confirmed
            # classification. Retain it for analysis, and confirm only the
            # mechanically established categories in this conservative release.
            review['proposed_clone_type'] = review['assessment']['classification']
            static = review.get('mechanical_source_review', {})
            review['assessment']['classification'] = static['classification'] if static.get('accepted') else 'unconfirmed'
            review['accepted'] = not audit['reasons']
            review.setdefault('screen_reasons', []).extend(audit['reasons'])
        review['adjudication'] = audit
        audit_rows.append(audit)
        reviews.append(review)
    # Do not require another costly review when a matched member already failed.
    # A pair which could otherwise be admitted must have both explicit reviews.
    audited = {a['candidate_id']: a for a in audit_rows}
    for r in records:
        if r['candidate_id'] not in pending_preservation:
            continue
        pair = [x for x in records if identity(x) == identity(r) and x['requested_clone_type'] == r['requested_clone_type']]
        if all(originals[x['candidate_id']]['accepted'] and
               not (set(audited[x['candidate_id']]['reasons']) - {'missing_candidate_preservation_audit'}) for x in pair):
            raise ValueError('Missing bound candidate preservation audit: ' + r['candidate_id'])
    accepted, quarantine, final_validation = admit(records, reviews)
    for row in accepted:
        v = next(v for v in final_validation if v['candidate_id'] == row['candidate_id'])
        row['proposed_clone_type'] = v['review'].get('proposed_clone_type')
        row['classification_policy'] = 'Mechanical Type 1/2 confirmation only; model-proposed Type 3/4 or other unsupported classification remains requested/unconfirmed.'
    return accepted, quarantine, final_validation, audit_rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', type=Path, required=True)
    p.add_argument('--decisions', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--snapshot', type=Path, default=DEFAULT_SNAPSHOT_DB)
    args = p.parse_args()
    if args.output.exists() and any(args.output.iterdir()):
        raise ValueError('Use a new empty adjudicated cohort version')
    records = read_jsonl(args.input / 'accepted.jsonl') + read_jsonl(args.input / 'quarantine.jsonl')
    if not records:
        raise ValueError('Provisional validation has not finished')
    report = json.loads((args.input / 'attrition.json').read_text(encoding='utf-8'))
    if report['reference_sha256'] != file_hash(args.snapshot):
        raise ValueError('Reference changed since provisional validation')
    from provtrail.corpus.integrations.sqlite_store import load_entries
    accepted, quarantine, validation, audits = finalize(records, read_jsonl(args.input / 'validation.jsonl'),
        read_jsonl(args.decisions), load_entries(args.snapshot))
    args.output.mkdir(parents=True, exist_ok=True)
    upstream = {p.name: {'path': str(p.resolve()), 'sha256': file_hash(p)} for p in sorted(args.input.iterdir()) if p.is_file()}
    for name in ('reviews.jsonl', 'attempts.jsonl', 'generation-lock.json', 'generation-settings.json', 'generated.jsonl'):
        shutil.copyfile(args.input / name, args.output / name)
    shutil.copyfile(args.decisions, args.output / 'source-adjudications.jsonl')
    for name, rows in [('accepted', accepted), ('quarantine', quarantine), ('validation', validation), ('adjudication', audits)]:
        write_jsonl(args.output / (name + '.jsonl'), rows)
    report['provisional_accepted_cases'] = report['accepted_cases']
    report.update(accepted_cases=len(accepted), quarantined_cases=len(quarantine),
        accepted_packages=dict(Counter(r['package_name'] for r in accepted)),
        accepted_requested_types=dict(Counter(r['requested_clone_type'] for r in accepted)),
        accepted_reviewed_types=dict(Counter(r['reviewed_clone_type'] for r in accepted)),
        accepted_proposed_types=dict(Counter(r.get('proposed_clone_type') for r in accepted)),
        accepted_by_provenance=dict(Counter('new' if r['candidate_id'].startswith('T2-') else 'historical' for r in accepted)),
        rejection_reasons=dict(Counter(reason for v in validation for reason in v['reasons'])),
        audit_policy='Second automated audit of extracted original security deltas, conservative literal/regex preservation screen, and paired re-admission. Never promotes rejected or unreviewed cases. Model clone classifications remain proposals unless mechanically confirmed.')
    for package in PACKAGES:
        report['shortfalls'][package].update(
            accepted_origins=len({identity(r) for r in accepted if r['package_name'] == package}),
            accepted_cases=sum(r['package_name'] == package for r in accepted),
            quarantined_cases=sum(r['package_name'] == package for r in quarantine))
    write_json(args.output / 'attrition.json', report)
    write_json(args.output / 'audit-lock.json', seal({'upstream': upstream,
        'decisions_sha256': file_hash(args.decisions), 'adjudication_code_sha256': file_hash(Path(__file__)),
        'outputs': {name: file_hash(args.output / name) for name in ('accepted.jsonl', 'quarantine.jsonl', 'validation.jsonl', 'adjudication.jsonl', 'source-adjudications.jsonl', 'attrition.json')}}))
    lines = ['# Validated Tier 2 cohort and attrition', '', report['review_policy'], '', report['audit_policy'], '',
        f"Inputs: {len(records)}. Provisional admissions: {report['provisional_accepted_cases']}. Final accepted: {len(accepted)}. Quarantined: {len(quarantine)}. Packages: {len(report['accepted_packages'])}.", '',
        '| Package | Accepted cases |', '|---|---:|']
    lines += [f'| {p} | {n} |' for p, n in sorted(report['accepted_packages'].items())]
    lines += ['', '| Expansion package | Selected origins / 10 | Accepted origins | Accepted cases / 40 |', '|---|---:|---:|---:|']
    lines += [f"| {p} | {s['selected_origins']} | {s['accepted_origins']} | {s['accepted_cases']} |" for p, s in report['shortfalls'].items()]
    lines += ['', 'All accepted cases are vulnerable/patched pairs per requested category. Requested Type 3/4 does not imply confirmed Type 3/4.',
        'Source adjudications and per-case preservation reviews are automated, not human validation. Executable tests are bounded litmus tests, not general equivalence proofs.',
        report['historical_provenance'], '', 'See validation.jsonl, adjudication.jsonl, source-adjudications.jsonl, and attrition.json for exact evidence, reasons, classifications, and provenance.']
    (args.output / 'attrition.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps({k: report[k] for k in ('accepted_cases', 'quarantined_cases', 'accepted_packages', 'accepted_by_provenance')}, indent=2))


if __name__ == '__main__':
    main()
