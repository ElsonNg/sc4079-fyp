"""Derive corrected quality summaries from preserved results; no inference or API calls."""
from collections import defaultdict
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from eval.ablation.common import digest, unseal, write_json
from eval.hash_summary_metrics import compute, cell, table
from eval import hash_summary_metrics as llm
from eval import hash_summary_metrics as hosted
from eval.hash_rule_impact import replay

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'eval/comparison_raw/hash-rule-summary-v1'
INPUTS = {}
CHANGES = []


def read(path, sealed=False):
    path = Path(path)
    data = path.read_bytes()
    INPUTS[str(path.relative_to(ROOT))] = hashlib.sha256(data).hexdigest()
    value = json.loads(data.decode('utf-8'))
    return unseal(value) if sealed else value


def corrected(row, scope):
    old = row['result']
    # Only mixed-side hashes can change under this rule. Single-side evidence
    # and every verification-only finding retain their original decisions.
    if old.get('hash_matches') and any(s['status'] == 'uncertain' for s in old['vulnerability_states']):
        new, changes = replay(old)
        if changes:
            expected = {s['fix_boundary_id'] for s in old['vulnerability_states']}
            # Changed cases in this corpus must have one expected hash boundary;
            # fail rather than infer attribution for a multi-boundary change.
            assert row['expected_hash_hit'] and len(expected) == 1
            vulnerable = {s['fix_boundary_id'] for s in new['vulnerability_states'] if s['status'] == 'vulnerable'}
            auto = new['priority'] == 'automatic_vulnerability'
            CHANGES.append(dict(scope=scope, candidate_id=row['candidate_id'], tier=row['tier'],
                                before=row['priority'], after=new['priority'], boundaries=changes))
            row = dict(row, priority=new['priority'], abstained=new['priority']=='manual_review',
                       correct_origin_automatic=row['expected_status']=='flagged' and auto and bool(vulnerable & expected),
                       wrong_origin_automatic=auto and bool(vulnerable-expected),
                       patched_false_positive=row['expected_status']=='cleared' and auto,
                       decision_details={
                           'boundaries': sorted([[s['fix_boundary_id'],s['status'],s.get('abstention_reason')] for s in new['vulnerability_states']]),
                           'lineages': sorted([[s['lineage_id'],s['confidence']] for s in new['lineages']])})
    return {k:v for k,v in row.items() if k != 'result'}


def gpu_study(name):
    root = ROOT / 'eval/frozen' / name
    old = read(root / 'combined/summary.json')
    lock = read(root / 'study-lock.json', True)
    summaries, all_rows = [], {}
    for config in lock['configurations']:
        cfg = config['name']
        directory = root / 'runs' / cfg / 'repeat-01'
        completion = read(directory / 'complete.json', True)
        assert completion['case_count'] == 1200 and completion['study'] == digest(lock)
        rows = [corrected(read(path, True)['row'], f'{name}/{cfg}') for path in sorted((directory/'checkpoints').glob('*.json'))]
        assert len(rows) == 1200 and len({r['candidate_id'] for r in rows}) == 1200
        all_rows[cfg] = rows
        for original in old['summaries']:
            if original['configuration'] != cfg:
                continue
            selected = [r for r in rows if r['tier']==original['tier'] and
                        (original['split']=='full' or r['split']==original['split'])]
            if original['scope']=='control_non_hash':
                # The rule does not affect any hash-route membership.
                non_hash = {r['candidate_id'] for r in all_rows['control'] if not r['hash_path']}
                selected = [r for r in selected if r['candidate_id'] in non_hash]
            quality = compute(selected)
            assert quality['labelled_cases'] == original['labelled_cases']
            summaries.append(dict(quality, configuration=cfg, tier=original['tier'],
                                  split=original['split'], scope=original['scope'],
                                  repetitions_complete=original['repetitions_complete']))
        print(f'Recomputed {name}/{cfg}: {len(rows)} first-pass cases',flush=True)
    result = deepcopy(old)
    result.update(summaries=summaries, method='Corrected hash-evidence replay; quality uses saved repetition 1 only',
                  timing_note='All timing and repetition metadata are historical; no fresh runtime/repeatability measurement',
                  original_study=lock['schema'])
    write_json(OUT / name / 'summary.json',result)
    return result, all_rows


def cpu_study(name,split):
    root=ROOT/'eval/frozen'/name
    old=read(root/'batch-runs/combined/summary.json')
    configs={s['configuration_id']:s['configuration'] for s in old['summaries']}
    selected={}
    paths=[root/'cases.jsonl',*sorted(root.glob('batch-runs/batch-*/run/cases.jsonl'))]
    for path in paths:
        if not path.exists(): continue
        sha=hashlib.sha256()
        with path.open('rb') as handle:
            for line in handle:
                sha.update(line)
                if not line.strip():continue
                row=json.loads(line)
                cid=row['configuration_id']
                assert cid in configs and row['split']==split
                key=(cid,row['tier'],row['candidate_id'])
                old_row={k:v for k,v in row.items() if k!='result'}
                # Duplicate baseline outputs are retained historically; use the
                # first source in the same ordering as the original reporter.
                if key in selected:continue
                selected[key]=corrected(row,f'{name}/{cid}')
        INPUTS[str(path.relative_to(ROOT))]=sha.hexdigest()
        print(f'Read CPU cases: {path.relative_to(ROOT)}',flush=True)
    groups=defaultdict(list)
    for (cid,tier,_),row in selected.items():groups[(cid,tier)].append(row)
    summaries=[]
    for original in old['summaries']:
        rows=groups[(original['configuration_id'],original['tier'])]
        quality=compute(rows)
        assert quality['labelled_cases']==original['labelled_cases']
        summaries.append(dict(quality,configuration_id=original['configuration_id'],
                              configuration=original['configuration'],experiments=original['experiments'],
                              tier=original['tier'],split=split))
    result=dict(summaries=summaries,method='Corrected hash-evidence replay of saved CPU rows',
                timing_note='Original single-pass CPU times retained; not measured for revised code')
    write_json(OUT/name/'summary.json',result)
    return result


def reviews(rows):
    root=ROOT/'eval/frozen/best-config-llm-review-v1'
    bundles=read(root/'review-inputs.json')['bundles']
    active={r['candidate_id'] for r in rows if r['abstained']}
    retained={cid:bundle for cid,bundle in bundles.items() if cid in active}
    assert len(active)==118 and set(retained)==active
    excluded=set(bundles)-active
    outcomes=[]
    for rep in range(1,4):
        opinions={}
        for cid in bundles:
            item=read(root/'reviews'/f'repeat-{rep:02d}'/(digest(cid)+'.json'),True)
            if cid in active:opinions[cid]=item['opinion']
        groups={tier:llm.summarize([r for r in rows if tier=='combined' or r['tier']==tier],opinions,retained)
                for tier in ('tier1','tier2','combined')}
        outcomes.append(dict(name='qwen3',model='qwen3:8b',repeat=rep,complete=True,
                             retained_reviews=len(opinions),groups=groups))
    for name in ('hosted-full-review-v1','gemini-pro-full-review-v1'):
        root=ROOT/'eval/frozen'/name
        saved=read(root/'combined/cases.json')
        originals=read(root/'combined/summary.json')
        for original in originals['passes']:
            if not original['complete']:continue
            label=original.get('name','gemini_pro')
            cases=next(p['cases'] for p in saved['passes'] if p['repeat']==original['repeat'] and
                       (name!='hosted-full-review-v1' or p['name']==label))
            results={c['case']:c for c in cases if c['case'] in active}
            assert len(results)==118
            groups={tier:hosted.pipeline_metrics([r for r in rows if tier=='combined' or r['tier']==tier],results,retained)
                    for tier in ('tier1','tier2','combined')}
            outcomes.append(dict(name=label,model=original.get('model',originals.get('model')),
                                 repeat=original['repeat'],complete=True,retained_reviews=118,groups=groups))
    result=dict(method='Reproject saved opinions onto corrected baseline; remove newly automatic case from review population',
                original_review_count=119,retained_review_count=118,excluded_cases=sorted(excluded),passes=outcomes,
                notes=['No new LLM calls or inference. Historical model timings/costs are not recomputed.',
                       'The incomplete DeepSeek 46/119 run remains incomplete and is excluded from pipeline comparisons.',
                       'Revised model review workload is 37 vulnerable-labelled + 81 patched-labelled cases.'])
    write_json(OUT/'llm-review/summary.json',result)
    return result


def main():
    comp,rows=gpu_study('active-component-ablation-gpu-v1')
    shortlist,_=gpu_study('active-shortlist-gpu-v1')
    cpu_study('active-tuning-v2','tuning')
    cpu_study('active-evaluation-shortlist-v2','evaluation')
    llms=reviews(rows['no_containment'])
    baseline={tier:compute([r for r in rows['no_containment'] if tier=='combined' or r['tier']==tier])
              for tier in ('tier1','tier2','combined')}
    write_json(OUT/'operating-point-summary.json',dict(method='Saved-evidence replay, not a fresh benchmark',metrics=baseline))
    lines=['# Findings and ablation: corrected hash-rule summary','',
           'Derived from saved evidence. Exact hashes take precedence within each fix boundary; shared abstracted hashes are ambiguous, not contradictory. Original frozen outputs remain unchanged.',
           '', 'No detector/model inference or API calls were made. Timings and repetitions remain historical.', '',
           '## Recommended operating point','',
           'K5/B10, R96/V3; hashing and contrastive ON; containment OFF; LLM OFF.','',
           table(['Tier','Automatic recall','Correct-origin recall','Precision','Patched FPR','Reviews'],
                 [[tier,*[cell(q[k]) for k in ('automatic_vulnerability_recall_all','correct_origin_automatic','automatic_vulnerability_precision','patched_fpr_all','abstained')]] for tier,q in baseline.items()]),'',
           'Only the Next.js case T1-3279232376a64d7faba3 changes in each hash-enabled configuration. The no-hash component remains unchanged. The affected case is in tuning; all four parameter evaluation-partition results are unchanged.', '',
           '## Reprojected LLM results','',
           'The corrected review population is 118 cases: 37 vulnerable-labelled and 81 patched-labelled. The removed case is now automatically classified, so its historical opinion no longer determines triage.', '',
           table(['Reviewer','Repeat','Auto/LLM recall','Origin recall','Precision','Patched FPR','Remaining reviews'],
                 [[p['name'],p['repeat'],*[cell(p['groups']['combined']['triage_projection'][k]) for k in
                   ('automatic_vulnerability_recall_all','correct_origin_automatic','automatic_vulnerability_precision','patched_fpr_all','abstained')]] for p in llms['passes']]),'',
           'SAST/SCA comparison results and the containment stress-test results are unchanged; the saved copied-code replay checked 6,522 function findings and found no changed verdicts.','',
           'The headline results remain retrospective advisory-labelled recognition, not proof that each extracted function is independently exploitable. A fresh baseline under a new compatible freeze remains useful before presenting revised-code runtime or repeatability claims.','',
           '## Reproducibility','',
           'Run `.venv/Scripts/python.exe -m eval.recompute_hash_summaries`. Derived JSON files are under `eval/comparison_raw/hash-rule-summary-v1/`; verification.json binds input and code hashes.']
    lines += ['', '## Component ablation (corrected first-pass quality)', '']
    for tier in ('tier1','tier2'):
        subset=[s for s in comp['summaries'] if s['tier']==tier and s['split']=='full' and s['scope']=='all']
        lines += ['### '+tier,'',table(['Setting','Automatic recall','Origin recall','Patched FPR','Reviews'],
                  [[s['configuration'],*[cell(s[k]) for k in ('automatic_vulnerability_recall_all','correct_origin_automatic','patched_fpr_all','abstained')]] for s in subset]),'']
    subset=[s for s in shortlist['summaries'] if s['tier']=='tier2' and s['split']=='evaluation' and s['scope']=='all']
    lines += ['## GPU parameter shortlist (evaluation; unchanged)', '',
              table(['Setting','Automatic recall','Origin recall','Patched FPR','Reviews'],
                    [[s['configuration'],*[cell(s[k]) for k in ('automatic_vulnerability_recall_all','correct_origin_automatic','patched_fpr_all','abstained')]] for s in subset]),'',
              'All 38 CPU tuning configurations now have Tier 1 origin recall 90/90, 6/91 patched alerts and zero reviews. Tier 2 CPU tuning results are unchanged. Hash-enabled full-cohort Tier 1 ablations now have 300/300 origin recall; the no-hash arm remains 269/300.', '',
              'Removing containment retains the same automatic/false-alert sets and reduces full-cohort reviews from 128 to 118. K5/B10 remains the recommended balance; the R64 and S0.80 evaluation tradeoffs are unchanged.']
    summary=ROOT/'docs/findings-ablation-summary.md'
    summary.write_text('\n'.join(lines)+'\n',encoding='utf-8')
    write_json(OUT/'changes.json',dict(changes=CHANGES,unique_changed_cases=sorted({c['candidate_id'] for c in CHANGES})))
    code=[Path(__file__),ROOT/'src/provtrail/pipeline/detection/hashing.py',ROOT/'src/provtrail/pipeline/models/boundary.py']
    write_json(OUT/'verification.json',dict(method='Saved-evidence recomputation',input_hashes=INPUTS,
               code_hashes={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in code},
               unique_changed_cases=sorted({c['candidate_id'] for c in CHANGES}),
               new_scans=0,new_model_calls=0,original_outputs_modified=False,
               summary_sha256=hashlib.sha256(summary.read_bytes()).hexdigest()))
    # Guard the expected impact across all independently saved configurations.
    assert {c['candidate_id'] for c in CHANGES}=={'T1-3279232376a64d7faba3'}
    assert len(CHANGES)==45  # 38 CPU tuning + 3 hash-enabled components + 4 GPU shortlist.
    assert baseline['combined']['automatic_vulnerability_recall_all']['count']==564
    assert baseline['combined']['correct_origin_automatic']['count']==559
    assert baseline['combined']['abstained']['count']==118
    assert baseline['combined']['patched_fpr_all']['count']==32
    print('Recomputed summary:',summary,flush=True)


if __name__=='__main__':main()
