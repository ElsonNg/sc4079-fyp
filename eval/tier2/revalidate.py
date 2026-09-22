"""Revalidate both candidate pools without changing an existing experiment freeze.

Individual evidence is separate from duplicate/pair eligibility. Unavailable context
is unresolved, never a demonstrated transformation defect. No model inference is used.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import importlib.metadata
import json
from pathlib import Path
import subprocess

from eval.ablation.common import (ROOT, append_jsonl, digest, entry_identity, file_hash,
    identity, read_jsonl, seal, source_key, unseal, write_json, write_jsonl)
from eval.ablation.freeze import tier1_targets, verify_manifest
from eval.common import DEFAULT_SNAPSHOT_DB
from eval.tier2.adjudicate import origin_key
from eval.tier2.cohort import screen
from eval.tier2.source_review import equivalence
from provtrail.corpus.integrations.sqlite_store import load_entries

SCRIPT = Path(__file__).with_name('boundary_checks.cjs')
HARNESSES = {
    ('qs', 'parseObject'): 'qs',
    ('qs', 'parseObjectRecursive'): 'qs',
    ('lodash', 'safeGet'): 'lodash',
    ('minimist', 'isConstructorOrProto'): 'minimist_predicate',
    ('semver', 'parse'): 'semver',
    ('moment', 'preprocessRFC2822'): 'moment',
    ('undici', 'shouldRemoveHeader'): 'headers',
    ('next', 'deleteLength'): 'framing',
    ('nuxt', 'encodeURL'): 'redirect_url',
    ('axios', 'beforeRedirect'): 'proxy_redirect',
    ('minimist', 'setKey'): 'minimist_set',
    ('nodemailer', '_handleAddress'): 'quoted_address',
    ('parse-server', 'verifyIdToken'): 'jwt_policy',
}
SCOPES = {
    'qs': 'Prototype assignment versus ordinary/numeric/array keys, parseArrays and plainObjects options. parseArrayValue is an identity stub. No full query-string parse integration.',
    'lodash': 'Prototype reads versus ordinary keys. objectProto is the VM Object.prototype.',
    'minimist_predicate': 'Constructor and __proto__ predicate versus ordinary keys; no command-line integration.',
    'semver': 'Length and exception guards with explicit regex and SemVer-constructor stubs; not full semver validation.',
    'moment': 'Nested-comment preprocessing and ordinary controls; no timing or ReDoS-bound proof.',
    'headers': 'Header removal across origins, content modes, casing and string/Buffer inputs. headerNameToString is explicitly stubbed as lowercase conversion.',
    'framing': 'DELETE/OPTIONS framing-header mutations, including existing transfer-encoding, zero/empty/null length and ordinary GET/POST controls.',
    'redirect_url': 'Same-origin leading-slash normalization, external-host branch and ordinary path/query/fragment controls; Node URL implementation.',
    'proxy_redirect': 'Stale proxy authorization removal and new proxy credentials on redirect. Uses the exact matching patched setProxy helper for all three functions to isolate the callback argument change. Environment proxy lookup is explicitly disabled.',
    'minimist_set': 'Final constructor and nested prototype keys versus ordinary assignments; matching original-side helper and fresh VM prototypes. No command-line parser integration.',
    'quoted_address': 'Quoted apparent address extraction versus ordinary tokens. No recursive group parser or SMTP integration.',
    'jwt_policy': 'JWT algorithm allowlist arguments plus cache defaults, invalid-token, issuer and subject paths. Key service and jwt.verify are observation stubs; no cryptographic verification is claimed.',
}


def outcome(observations, side):
    a, b, c = observations
    if not a['ok'] or not b['ok']:
        return 'inconclusive_reference_execution'
    if a['value'] == b['value']:
        return 'inconclusive_non_distinguishing_test'
    if not c['ok']:
        return 'candidate_compile_error' if c.get('phase') == 'compile' else 'behaviour_mismatch'
    return 'pass' if c['value'] == (a if side == 'flagged' else b)['value'] else 'behaviour_mismatch'


def executable(record, entry, entries):
    name = HARNESSES.get((entry.advisory.package_name, entry.origin.function_name))
    if name is None:
        return None
    payload = {'harness': name, 'language': entry.origin.source_language,
        'sources': [entry.vulnerable_function, entry.patched_function, record['candidate_source']]}
    context = []
    if name in {'proxy_redirect', 'minimist_set'}:
        fn = 'setProxy' if name == 'proxy_redirect' else 'isConstructorOrProto'
        matches = [e for e in entries if e.advisory.package_name == entry.advisory.package_name
            and e.origin.fix_commit_sha == entry.origin.fix_commit_sha and e.origin.function_name == fn]
        if not matches:
            return {'harness': name, 'status': 'inconclusive_missing_matching_helper'}
        helper = matches[0]
        context = [helper.model_dump()]
        if name == 'proxy_redirect':
            payload['helpers'] = [helper.patched_function] * 3
        else:
            payload['helpers'] = [helper.vulnerable_function, helper.patched_function,
                helper.vulnerable_function if record['expected_status'] == 'flagged' else helper.patched_function]
    evidence = {'harness': name, 'scope': SCOPES[name], 'harness_sha256': file_hash(SCRIPT),
        'source_hashes': [digest(s) for s in payload['sources']], 'supporting_context': context,
        'method': 'executable_security_boundary', 'reviewer_type': 'automated'}
    try:
        result = subprocess.run(['node', '--max-old-space-size=128', str(SCRIPT)],
            input=json.dumps(payload), text=True, capture_output=True, timeout=12, check=True)
        evidence['execution'] = json.loads(result.stdout)
        evidence['status'] = outcome(evidence['execution']['observations'], record['expected_status'])
    except (subprocess.SubprocessError, OSError, ValueError) as exc:
        evidence.update(status='inconclusive_execution', error=str(exc))
    return evidence


def bound_decision(record, entry, decisions, references):
    decision = decisions.get(origin_key(record))
    if decision is None:
        return None
    if (decision.get('vulnerable_source_sha256') != digest(entry.vulnerable_function)
            or decision.get('patched_source_sha256') != digest(entry.patched_function)
            or tuple(decision['origin']) != entry_identity(entry)):
        raise ValueError('Source review identity mismatch')
    for side in ('vulnerable', 'patched'):
        quote = decision.get(side + '_quote')
        if not quote or quote not in getattr(entry, side + '_function'):
            raise ValueError('Source review quotation mismatch')
    for helper in decision.get('supporting_reference_context', []):
        if identity(helper)[1] != identity(record)[1] or references.get(identity(helper)) != helper:
            raise ValueError('Source review helper mismatch')
    return decision


def assess(record, entry, entries, decisions, references, previous):
    row = {k: record.get(k) for k in ('candidate_id', 'tier', 'package_name', 'source_language', 'expected_status')}
    row.update(candidate_sha256=digest(record.get('candidate_source', '')), origin=list(identity(record)),
        status='needs_review', reasons=[], reviewer_type='automated',
        reviewer='Deterministic boundary tests and bound source audits; no new model inference or human review',
        requested_clone_type=record.get('requested_clone_type', record.get('clone_type')),
        confirmed_clone_type='unconfirmed')
    if entry is None or record.get('unavailable_source'):
        row.update(status='reference_source_mismatch', reasons=['Historical target source is not identical to the current reference source; no current-reference substitution performed.'],
            historical_source_evidence=record.get('historical_source_evidence'))
        return row
    reasons, diagnostic = screen(record, entry)
    row.update(screen_reasons=reasons, diagnostic_screen=diagnostic)
    if reasons:
        row.update(status='source_or_parse_mismatch', reasons=reasons)
        return row
    test = executable(record, entry, entries)
    row['executable_evidence'] = test
    expected = entry.vulnerable_function if record['expected_status'] == 'flagged' else entry.patched_function
    mechanical = equivalence(expected, record['candidate_source'], record['source_language'])
    row['mechanical_preservation'] = mechanical
    if mechanical['preserved']:
        row['confirmed_clone_type'] = mechanical['classification']
    decision = bound_decision(record, entry, decisions, references)
    row['source_delta_review'] = decision
    candidate_review = next((c for c in (decision or {}).get('candidate_reviews', [])
        if c['candidate_id'] == record['candidate_id'] and c['candidate_sha256'] == row['candidate_sha256']), None)
    row['candidate_preservation_review'] = candidate_review
    if test and test['status'] == 'candidate_compile_error':
        row.update(status='failed_runtime_parse', reasons=['Node rejects the candidate function; both reference functions compile and produce distinguishing observations.'])
        return row
    if test and test['status'] == 'pass' and not (candidate_review and not candidate_review['accepted']):
        row['status'] = 'validated_executable'
        return row
    if test and test['status'] == 'behaviour_mismatch':
        row.update(status='failed_behaviour', reasons=['Candidate differs from its labelled original on the recorded executable inputs and explicit dependency stubs (including candidate exceptions).'])
        return row
    if candidate_review and not candidate_review['accepted']:
        row['reasons'].append('Earlier bound preservation review identified a change not discharged by the bounded test; additional review required.')
        return row
    if decision and decision['supported']:
        if record['tier'] == 'tier1' or mechanical['preserved'] or (candidate_review and candidate_review['accepted']):
            row['status'] = 'validated_source_review'
        else:
            row['reasons'].append('Security change reviewed; transformation still requires preservation evidence.')
    else:
        row['reasons'].append('Original extracted security change lacks sufficient supported evidence.')
    prior = previous.get(record['candidate_id'])
    if prior:
        row['previous_experiment_admitted'] = prior['accepted']
        row['previous_reasons'] = prior['reasons']
    return row


def pair_eligibility(records, validations):
    by_id = {r['candidate_id']: r for r in validations}
    counts = Counter(source_key(r['candidate_source'], r['source_language']) for r in records)
    groups = defaultdict(list)
    for record in records:
        groups[(identity(record), record.get('requested_clone_type', record['clone_type']))].append(record)
    eligible = []
    for pair in groups.values():
        complete = len(pair) == 2 and {r['expected_status'] for r in pair} == {'flagged', 'cleared'}
        good = complete and all(by_id[r['candidate_id']]['status'].startswith('validated_')
            and counts[source_key(r['candidate_source'], r['source_language'])] == 1 for r in pair)
        for record in pair:
            row = by_id[record['candidate_id']]
            row.update(pair_complete=complete, duplicate_source_count=counts[source_key(record['candidate_source'], record['source_language'])],
                paired_experiment_eligible=good)
            if good:
                eligible.append(dict(record, reviewed_clone_type=row['confirmed_clone_type'],
                    clone_type_status='requested_unconfirmed' if row['confirmed_clone_type'] == 'unconfirmed' else 'reviewed'))
    return eligible


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--resume', action='store_true')
    args = p.parse_args()
    frozen = ROOT / 'eval/frozen'
    manifest = frozen / 'experiment-v2/manifest.json'
    verify_manifest(manifest)
    paths = [DEFAULT_SNAPSHOT_DB, manifest, ROOT / 'eval/tier1_curated_labels.jsonl',
        frozen / 'tier2-v2/accepted.jsonl', frozen / 'tier2-v2/quarantine.jsonl',
        frozen / 'tier2-v2/validation.jsonl', frozen / 'tier2-v2/source-adjudications.jsonl',
        Path(__file__), SCRIPT, Path(__file__).with_name('behaviour.py'), Path(__file__).with_name('behaviour.cjs'),
        Path(__file__).with_name('source_review.py'), Path(__file__).with_name('cohort.py'),
        ROOT / 'eval/ablation/common.py', ROOT / 'eval/ablation/freeze.py', Path(__file__).with_name('adjudicate.py')]
    lock = {'schema': 'corpus-revalidation-v1', 'inputs': {str(x.resolve()): file_hash(x) for x in paths},
        'node': subprocess.check_output(['node','--version'], text=True).strip(),
        'dependencies': {name: importlib.metadata.version(name) for name in ('tree-sitter','tree-sitter-javascript','tree-sitter-typescript')}}
    args.output.mkdir(parents=True, exist_ok=True)
    lock_path = args.output / 'lock.json'
    if lock_path.exists():
        if not args.resume or unseal(json.loads(lock_path.read_text())) != lock:
            raise ValueError('Output exists or resume code/data/environment mismatch')
    else:
        if any(args.output.iterdir()):
            raise ValueError('Use an empty versioned output directory')
        write_json(lock_path, seal(lock))
    entries = load_entries(DEFAULT_SNAPSHOT_DB)
    by_origin = {entry_identity(e): e for e in entries}
    references = {key: e.model_dump() for key, e in by_origin.items()}
    decisions = {r['origin_key']: r for r in read_jsonl(frozen / 'tier2-v2/source-adjudications.jsonl')}
    previous = {r['candidate_id']: r for r in read_jsonl(frozen / 'tier2-v2/validation.jsonl')}
    tier2 = [dict(r, tier='tier2') for name in ('accepted', 'quarantine') for r in read_jsonl(frozen / f'tier2-v2/{name}.jsonl')]
    tier1, excluded = tier1_targets(read_jsonl(ROOT / 'eval/tier1_curated_labels.jsonl'), entries)
    for r in tier1:
        e = by_origin[identity(r)]
        r.update(vulnerable_function=e.vulnerable_function, patched_function=e.patched_function,
            vulnerable_source_sha256=digest(e.vulnerable_function), patched_source_sha256=digest(e.patched_function))
    for r in excluded:
        historical = next((x for x in tier2 if identity(x) == identity(r) and digest(
            x['vulnerable_function'] if r['expected_status'] == 'flagged' else x['patched_function']) == r['target_source_sha256']), None)
        if historical:
            source = historical['vulnerable_function'] if r['expected_status'] == 'flagged' else historical['patched_function']
            r.update(candidate_source=source, historical_source_evidence={
                'candidate_id': historical['candidate_id'], 'sha256': digest(source),
                'provenance': 'Exact historical target source recovered from a preserved Tier 2 embedded original with matching origin and target hash. Still mismatches the current reference.'})
        tier1.append(dict(r, unavailable_source=True))
    records = sorted(tier1 + tier2, key=lambda r: (r['tier'], r['candidate_id']))
    if len({r['candidate_id'] for r in records}) != len(records):
        raise ValueError('Duplicate candidate IDs')
    journal = args.output / 'checks.jsonl'
    cached = {}
    for sealed in read_jsonl(journal):
        item = unseal(sealed)
        if item['candidate_id'] in cached:
            raise ValueError('Duplicate checkpoint')
        cached[item['candidate_id']] = item
    if set(cached) - {r['candidate_id'] for r in records}:
        raise ValueError('Unexpected checkpoint candidate')
    validations = []
    for i, record in enumerate(records):
        key = digest([lock, record])
        item = cached.get(record['candidate_id'])
        if item and item['key'] != key:
            raise ValueError('Checkpoint candidate/configuration mismatch')
        if not item:
            result = assess(record, by_origin.get(identity(record)), entries, decisions, references, previous)
            item = {'candidate_id': record['candidate_id'], 'key': key, 'result': result}
            append_jsonl(journal, seal(item))
        validations.append(item['result'])
        if (i+1) % 100 == 0:
            print(f'Checked {i+1}/{len(records)}', flush=True)
    paired = pair_eligibility(tier2, validations)
    write_jsonl(args.output / 'validation.jsonl', validations)
    write_jsonl(args.output / 'tier2-paired.jsonl', paired)
    write_jsonl(args.output / 'tier1-validated.jsonl', [r for r in tier1 if next(v for v in validations if v['candidate_id'] == r['candidate_id'])['status'].startswith('validated_')])
    summary = {}
    for tier in ('tier1', 'tier2'):
        rows = [r for r in validations if r['tier'] == tier]
        summary[tier] = {'total': len(rows), 'statuses': dict(Counter(r['status'] for r in rows)),
            'validated': sum(r['status'].startswith('validated_') for r in rows),
            'packages': {package: dict(Counter(r['status'] for r in rows if r['package_name'] == package)) for package in sorted({r['package_name'] for r in rows})}}
    summary['tier2'].update(paired_eligible=len(paired), paired_packages=dict(Counter(r['package_name'] for r in paired)),
        confirmed_clone_types=dict(Counter(v['confirmed_clone_type'] for v in validations if v.get('paired_experiment_eligible'))))
    summary['tier1']['historical_targets_recovered_but_reference_mismatched'] = sum(bool(v.get('historical_source_evidence')) for v in validations if v['tier']=='tier1')
    followup = defaultdict(list)
    for v in validations:
        if not v['status'].startswith('validated_'):
            followup[(v['tier'], tuple(v['origin']), v['status'])].append(v)
    tasks=[]
    for (tier, origin, status), rows in sorted(followup.items(), key=lambda x:str(x[0])):
        first=rows[0]
        tasks.append(dict(tier=tier, origin=list(origin), package=first['package_name'], status=status,
            candidate_ids=[v['candidate_id'] for v in rows], reasons=sorted({s for v in rows for s in v['reasons']}),
            source_review_reason=(first.get('source_delta_review') or {}).get('reason'),
            next_action=('Repair or replace the transformation in a new version, retaining this failure evidence.' if status.startswith('failed_') else
                'Reconcile the historical target and reference extraction; preserve both original hashes.' if 'mismatch' in status else
                'Supply the exact matching helper/package context or review the complete security patch and candidate preservation.')))
    write_jsonl(args.output / 'followup.jsonl', tasks)
    summary['scope'] = 'All input cases assessed. Validation means recorded bounded executable or source-review evidence, not proof of full package security. Unresolved cases remain excluded. Pair/duplicate eligibility is separate. No human validation, release refetch, new generation, freeze replacement, or full ablations.'
    write_json(args.output / 'summary.json', summary)
    lines = ['# Corpus revalidation', '', summary['scope'], '',
        '| Tier | Candidates | Validated individually | Executable | Source review | Behaviour mismatch | Runtime parse failure | Unresolved / source issues |',
        '|---|---:|---:|---:|---:|---:|---:|---:|']
    for tier in ('tier1', 'tier2'):
        s=summary[tier]; c=s['statuses']
        lines.append(f"| {tier} | {s['total']} | {s['validated']} | {c.get('validated_executable',0)} | {c.get('validated_source_review',0)} | {c.get('failed_behaviour',0)} | {c.get('failed_runtime_parse',0)} | {s['total']-s['validated']-c.get('failed_behaviour',0)-c.get('failed_runtime_parse',0)} |")
    lines += ['', f'Tier 2 complete, unique, validated pairs: {len(paired)} cases ({len(paired)//2} pairs).',
        'These are proposed newly eligible fixtures, not a replacement of the active experiment-v2 freeze. Clone Type 3/4 claims remain unconfirmed.',
        f"Of 18 Tier 1 reference mismatches, {summary['tier1']['historical_targets_recovered_but_reference_mismatched']} exact historical target sources were located in the preserved Tier 2 originals. Their security validation and reconciliation with the current reference remain pending; no replacement source was silently substituted.",
        '', '## Per-package evidence', '', '| Package | Tier 1 validated / total | Tier 2 validated / total | Tier 2 paired |', '|---|---:|---:|---:|']
    for package in sorted({r['package_name'] for r in validations}):
        counts=[]
        for tier in ('tier1','tier2'):
            rows=[r for r in validations if r['tier']==tier and r['package_name']==package]
            counts.append(f"{sum(r['status'].startswith('validated_') for r in rows)} / {len(rows)}")
        lines.append(f"| {package} | {counts[0]} | {counts[1]} | {summary['tier2']['paired_packages'].get(package,0)} |")
    lines += ['', '## Recorded failures', '', 'Executable mismatches are relative to the explicit harness inputs and stubs. They do not establish exploitability of an entire package.', '']
    lines += [f"- {r['candidate_id']} ({r['package_name']}): {r['status']}, {r['executable_evidence'].get('harness')}" for r in validations if r['status'].startswith('failed_')]
    lines += ['', 'See validation.jsonl for every case, exact observations, bound original/candidate hashes, diagnostics, prior source audits and unresolved reasons. followup.jsonl groups remaining work by tier/origin/status. checks.jsonl contains sealed resumable checkpoints; lock.json pins inputs, code and parser/Node versions.',
        '', 'Reproduce:', '', '```powershell', f'.venv/Scripts/python.exe -m eval.tier2.revalidate --output {args.output.as_posix()} --resume', '```',
        'For an independent fresh run, use a new empty output directory and omit --resume.']
    (args.output / 'report.md').write_text('\n'.join(lines)+'\n', encoding='utf-8')
    verify_manifest(manifest)
    write_json(args.output / 'output-lock.json', seal({
        'run_lock_sha256': file_hash(lock_path), 'active_manifest_verified': True,
        'outputs': {name: file_hash(args.output / name) for name in ('validation.jsonl','tier2-paired.jsonl','tier1-validated.jsonl','summary.json','report.md','checks.jsonl','followup.jsonl')}}))
    print(json.dumps({tier:{k:v for k,v in summary[tier].items() if k!='packages'} for tier in ('tier1','tier2')}, indent=2))


if __name__ == '__main__':
    main()
