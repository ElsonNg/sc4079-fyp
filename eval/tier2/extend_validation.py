"""Extend a sealed validation report with another bounded executable batch.

Untouched results are inherited from verified records. Both old code and fixtures
remain intact. This produces validation evidence, not a new detector experiment.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import copy
import importlib
import importlib.metadata
import json
from pathlib import Path
import subprocess

from eval.ablation.common import (ROOT,append_jsonl,digest,entry_identity,file_hash,identity,
    read_jsonl,seal,unseal,write_json,write_jsonl)
from eval.ablation.freeze import tier1_targets,verify_manifest
from eval.common import DEFAULT_SNAPSHOT_DB
from eval.tier2 import revalidate
from provtrail.corpus.integrations.sqlite_store import load_entries


def verify_previous(directory):
    """Verify actual evidence and its original inputs before inheriting a verdict."""
    directory=Path(directory)
    output=unseal(json.loads((directory/'output-lock.json').read_text(encoding='utf-8')))
    if output['run_lock_sha256']!=file_hash(directory/'lock.json'):
        raise ValueError('Previous run lock mismatch')
    for name,expected in output['outputs'].items():
        if Path(name).name!=name or file_hash(directory/name)!=expected:
            raise ValueError('Previous output mismatch: '+name)
    lock=unseal(json.loads((directory/'lock.json').read_text(encoding='utf-8')))
    for path,expected in lock['inputs'].items():
        if file_hash(Path(path))!=expected:
            raise ValueError('Previous input/code mismatch: '+path)
    for name,version in lock.get('dependencies',{}).items():
        if importlib.metadata.version(name)!=version:
            raise ValueError('Previous dependency mismatch: '+name)
    if lock.get('node')!=subprocess.check_output(['node','--version'],text=True).strip():
        raise ValueError('Previous Node version mismatch')
    return lock


def build_records(entries):
    base=ROOT/'eval/frozen/tier2-v2'
    tier2=[dict(r,tier='tier2') for name in ('accepted','quarantine') for r in read_jsonl(base/(name+'.jsonl'))]
    by_origin={entry_identity(e):e for e in entries}
    tier1,excluded=tier1_targets(read_jsonl(ROOT/'eval/tier1_curated_labels.jsonl'),entries)
    for r in tier1:
        e=by_origin[identity(r)]
        r.update(vulnerable_function=e.vulnerable_function,patched_function=e.patched_function,
            vulnerable_source_sha256=digest(e.vulnerable_function),patched_source_sha256=digest(e.patched_function))
    for r in excluded:
        historical=next((x for x in tier2 if identity(x)==identity(r) and digest(
            x['vulnerable_function'] if r['expected_status']=='flagged' else x['patched_function'])==r['target_source_sha256']),None)
        if historical:
            r['candidate_source']=historical['vulnerable_function'] if r['expected_status']=='flagged' else historical['patched_function']
        r['unavailable_source']=True
    return sorted(tier1+excluded+tier2,key=lambda r:(r['tier'],r['candidate_id']))


def validate_checkpoint(item,key,candidate_id):
    decoded=unseal(item)
    if decoded['candidate_id']!=candidate_id or decoded['key']!=key:
        raise ValueError('Checkpoint candidate/configuration mismatch')
    return decoded['result']


def summarize(rows,fixtures,previous):
    summary={}
    for tier in ('tier1','tier2'):
        selected=[r for r in rows if r['tier']==tier]
        summary[tier]=dict(total=len(selected),statuses=dict(Counter(r['status'] for r in selected)),
            validated=sum(r['status'].startswith('validated_') for r in selected),
            packages={p:dict(Counter(r['status'] for r in selected if r['package_name']==p)) for p in sorted({r['package_name'] for r in selected})})
    summary['tier2'].update(paired_eligible=len(fixtures),paired_packages=dict(Counter(r['package_name'] for r in fixtures)),
        confirmed_clone_types=dict(Counter(r['reviewed_clone_type'] for r in fixtures)))
    changed=[r for r in rows if r['status']!=previous[r['candidate_id']]['status']]
    summary['transitions']=[dict(tier=tier,before=before,after=after,cases=n) for (tier,before,after),n in
        sorted(Counter((r['tier'],previous[r['candidate_id']]['status'],r['status']) for r in changed).items())]
    summary['scope']='New security-boundary tests for selected origins; other evidence inherited from verified prior records. Automated extracted-function validation with explicit stubs, not human vetting or full-package exploit testing. Active experiment freeze and original fixtures remain unchanged. Requested clone categories remain unconfirmed unless mechanically established.'
    return summary,changed


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--previous',type=Path,default=ROOT/'eval/frozen/revalidation-v2')
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--resume',action='store_true')
    p.add_argument('--suite',default='eval.tier2.additional_checks',help='Versioned Python module exposing HARNESSES, SCRIPT, selected and check')
    args=p.parse_args()
    suite=importlib.import_module(args.suite)
    prior_lock=verify_previous(args.previous)
    manifest=ROOT/'eval/frozen/experiment-v2/manifest.json'
    verify_manifest(manifest)
    paths=[Path(__file__),Path(suite.__file__),suite.SCRIPT,*getattr(suite,'SUPPORT_FILES',[]),
        args.previous/'lock.json',args.previous/'output-lock.json',args.previous/'validation.jsonl',
        ROOT/'eval/frozen/tier2-v2/source-adjudications.jsonl',ROOT/'eval/frozen/tier2-v2/validation.jsonl']
    lock=dict(schema='additional-corpus-validation-v1',inputs=dict(prior_lock['inputs'],**{str(p.resolve()):file_hash(p) for p in paths}),
        node=prior_lock['node'],dependencies=prior_lock['dependencies'],previous=str(args.previous.resolve()),suite=args.suite,
        harnesses=sorted((p,f,h) for (p,f),h in suite.HARNESSES.items()))
    args.output.mkdir(parents=True,exist_ok=True)
    run_lock=args.output/'lock.json'
    if run_lock.exists():
        if not args.resume or unseal(json.loads(run_lock.read_text()))!=json.loads(json.dumps(lock)):
            raise ValueError('Existing output or resume code/data/environment mismatch')
    else:
        if any(args.output.iterdir()):raise ValueError('Use an empty versioned output directory')
        write_json(run_lock,seal(lock))
    entries=load_entries(DEFAULT_SNAPSHOT_DB)
    by_origin={entry_identity(e):e for e in entries}
    references={key:e.model_dump() for key,e in by_origin.items()}
    decisions={r['origin_key']:r for r in read_jsonl(ROOT/'eval/frozen/tier2-v2/source-adjudications.jsonl')}
    old_reviews={r['candidate_id']:r for r in read_jsonl(ROOT/'eval/frozen/tier2-v2/validation.jsonl')}
    prior_rows=read_jsonl(args.previous/'validation.jsonl')
    previous={r['candidate_id']:r for r in prior_rows}
    records=build_records(entries)
    if len(previous)!=len(prior_rows) or set(previous)!={r['candidate_id'] for r in records}:
        raise ValueError('Prior candidate identities differ')
    journal=args.output/'checks.jsonl'
    checkpoints={}
    for item in read_jsonl(journal):
        candidate_id=unseal(item)['candidate_id']
        if candidate_id in checkpoints:raise ValueError('Duplicate checkpoint')
        checkpoints[candidate_id]=item
    selected_ids={r['candidate_id'] for r in records if not r.get('unavailable_source') and identity(r) in by_origin and suite.selected(by_origin[identity(r)])}
    if set(checkpoints)-selected_ids:raise ValueError('Unexpected checkpoint')
    rows=[]
    old_executable=revalidate.executable
    try:
        # Reuse unchanged identity/admission rules with a explicitly pinned test provider.
        revalidate.executable=suite.check
        for record in records:
            candidate_id=record['candidate_id']
            if previous[candidate_id]['candidate_sha256']!=digest(record.get('candidate_source','')):
                raise ValueError('Previous candidate source mismatch: '+candidate_id)
            if candidate_id not in selected_ids:
                row=copy.deepcopy(previous[candidate_id])
                row['evidence_inherited_from']=str((args.previous/'validation.jsonl').resolve())
            else:
                key=digest([lock,record,previous[candidate_id]])
                if candidate_id in checkpoints:
                    row=validate_checkpoint(checkpoints[candidate_id],key,candidate_id)
                else:
                    row=revalidate.assess(record,by_origin[identity(record)],entries,decisions,references,old_reviews)
                    row['previous_validation_status']=previous[candidate_id]['status']
                    append_jsonl(journal,seal(dict(candidate_id=candidate_id,key=key,result=row)))
            rows.append(row)
    finally:
        revalidate.executable=old_executable
    paired=revalidate.pair_eligibility([r for r in records if r['tier']=='tier2'],rows)
    summary,changed=summarize(rows,paired,previous)
    summary.update(cases_rechecked=len(selected_ids),origins_rechecked=len({identity(r) for r in records if r['candidate_id'] in selected_ids}),
        previous_report=str(args.previous.resolve()),newly_supported=sum(r['status'].startswith('validated_') and not previous[r['candidate_id']]['status'].startswith('validated_') for r in changed))
    write_jsonl(args.output/'validation.jsonl',rows)
    write_jsonl(args.output/'changes.jsonl',[dict(candidate_id=r['candidate_id'],tier=r['tier'],package=r['package_name'],origin=r['origin'],before=previous[r['candidate_id']]['status'],after=r['status'],harness=(r.get('executable_evidence') or {}).get('harness')) for r in changed])
    write_jsonl(args.output/'tier2-paired.jsonl',paired)
    valid_ids={r['candidate_id'] for r in rows if r['status'].startswith('validated_')}
    write_jsonl(args.output/'tier1-validated.jsonl',[r for r in records if r['tier']=='tier1' and r['candidate_id'] in valid_ids])
    grouped=defaultdict(list)
    for r in rows:
        if not r['status'].startswith('validated_'):grouped[(r['tier'],tuple(r['origin']),r['status'])].append(r)
    followup=[]
    for (tier,origin,status),group in sorted(grouped.items(),key=lambda x:str(x[0])):
        followup.append(dict(tier=tier,origin=list(origin),package=group[0]['package_name'],status=status,
            candidate_ids=[r['candidate_id'] for r in group],reasons=sorted({reason for r in group for reason in r['reasons']}),
            next_action='Repair in a new fixture version or exclude; retain failure evidence.' if status.startswith('failed_') else
            'Reconcile historical and reference sources.' if 'mismatch' in status else 'Add exact helper context, a distinguishing test, or a documented source/preservation review.'))
    write_jsonl(args.output/'followup.jsonl',followup)
    summary['unresolved_origins']=len({tuple(r['origin']) for r in followup if not r['status'].startswith('failed_')})
    write_json(args.output/'summary.json',summary)
    lines=['# Continued corpus validation','',summary['scope'],'',
        f"Rechecked {summary['cases_rechecked']} cases across {summary['origins_rechecked']} reference origins. Newly supported cases: {summary['newly_supported']}.",'',
        '| Tier | Total candidates | Supported | Failed checks | Unresolved |','|---|---:|---:|---:|---:|']
    for tier in ('tier1','tier2'):
        s=summary[tier];failed=sum(n for status,n in s['statuses'].items() if status.startswith('failed_'))
        lines.append(f"| {tier} | {s['total']} | {s['validated']} | {failed} | {s['total']-s['validated']-failed} |")
    lines+=['',f"Tier 2 pair/duplicate-eligible subset: {len(paired)} cases ({len(paired)//2} pairs), {len(summary['tier2']['paired_packages'])} packages.",
        f"Unresolved cases span {summary['unresolved_origins']} advisory/fix/function origins. The complete candidate pools remain 600 and 788.",'',
        '| Tier | Previous outcome | New outcome | Cases |','|---|---|---|---:|']
    lines += [f"| {r['tier']} | {r['before']} | {r['after']} | {r['cases']} |" for r in summary['transitions']]
    lines+=['','The new harnesses require an explicit security witness: it must be absent in the vulnerable original and present in the patched original. The candidate must match its labelled original across that witness and all controls. Mere output differences do not establish the security label.',
        'Existing bound negative candidate reviews remain unresolved even if the new bounded tests pass. A test that contradicts a previous admission is recorded as a failure; previous records are preserved.',
        'Executable observations include explicit helper/stub assumptions. They are not proof of complete semantic equivalence or package exploitability. No clone Type 3/4 confirmation is inferred from a behavioural pass.',
        '', 'See changes.jsonl for transitions, validation.jsonl for every case, checks.jsonl for new executable evidence, and followup.jsonl for remaining work.',
        '', '```powershell',f'.venv/Scripts/python.exe -m eval.tier2.extend_validation --previous {args.previous.as_posix()} --suite {args.suite} --output {args.output.as_posix()} --resume','```',
        'For a fresh run use another empty output directory and omit --resume. The prior report, original inputs, code, Node and parser versions must still match their sealed records.']
    (args.output/'report.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    verify_previous(args.previous)
    verify_manifest(manifest)
    write_json(args.output/'output-lock.json',seal(dict(run_lock_sha256=file_hash(run_lock),active_manifest_verified=True,
        outputs={name:file_hash(args.output/name) for name in ('checks.jsonl','validation.jsonl','changes.jsonl','summary.json','report.md','tier1-validated.jsonl','tier2-paired.jsonl','followup.jsonl')})))
    print(json.dumps({k:({key:value for key,value in v.items() if key!='packages'} if k in {'tier1','tier2'} else v) for k,v in summary.items()},indent=2))


if __name__=='__main__':main()
