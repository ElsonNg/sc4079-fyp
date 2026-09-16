"""Aggregate the frozen baseline and fresh default-off-option benchmark outputs."""
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SUITES=[
 ('llm_transformed','llm_transformed_results_contrastive_containment_v3.json','llm_transformed_results_local_correspondence.json'),
 ('deterministic','wider_deterministic_fixture_contrastive_containment_v3.json','wider_deterministic_fixture_local_correspondence.json'),
 ('klaban','wider_klaban_fixture_contrastive_containment_v3.json','wider_klaban_fixture_local_correspondence.json'),
]
QUARANTINE={'C10','C30','N-P30','N-B02','L070','L076','L095'}

def counts(rows,key):return dict(Counter(r[key] for r in rows))

def main():
    all_rows=[]; suites={}
    for name,baseline_name,enabled_name in SUITES:
        baseline=json.loads((ROOT/'eval'/baseline_name).read_text())
        enabled=json.loads((ROOT/'eval'/enabled_name).read_text())
        old={r['candidate_id']:r for r in baseline['results']}
        new={r['candidate_id']:r for r in enabled['results']}
        assert old.keys()==new.keys()
        rows=[]
        for cid in old:
            used=[b for b in new[cid]['boundary_verification'] if b.get('local_correspondence_used')]
            row={'suite':name,'candidate_id':cid,'expected_status':new[cid]['expected_status'],
                 'included_in_reviewed':cid not in QUARANTINE,
                 'baseline_outcome':old[cid]['outcome'],'enabled_outcome':new[cid]['outcome'],
                 'baseline_priority':old[cid]['priority'],'enabled_priority':new[cid]['priority'],
                 'used_boundaries':used}
            rows.append(row);all_rows.append(row)
        suites[name]={'sample_count':len(rows),'baseline':counts(rows,'baseline_outcome'),
                      'enabled':counts(rows,'enabled_outcome'),
                      'changed':[r['candidate_id'] for r in rows if r['baseline_outcome']!=r['enabled_outcome']],
                      'fallback_used_candidates':[r['candidate_id'] for r in rows if r['used_boundaries']]}
    summary={}
    for label,rows in [('original',all_rows),('reviewed',[r for r in all_rows if r['included_in_reviewed']])]:
        changed=[r for r in rows if r['baseline_outcome']!=r['enabled_outcome']]
        summary[label]={'sample_count':len(rows),'baseline':counts(rows,'baseline_outcome'),
                        'enabled':counts(rows,'enabled_outcome'),'changed_count':len(changed),
                        'new_errors':[r['candidate_id'] for r in changed if r['enabled_outcome'] in {'false_positive','false_negative'}]}
    summary['fallback_attempted_boundaries']=sum(
        sum(b.get('local_correspondence_attempted',False) for b in r['boundary_verification'])
        for _,_,f in SUITES for r in json.loads((ROOT/'eval'/f).read_text())['results'])
    summary['fallback_used_boundaries']=sum(len(r['used_boundaries']) for r in all_rows)
    summary['changed']=[{k:r[k] for k in ['suite','candidate_id','baseline_outcome','enabled_outcome']} for r in all_rows if r['baseline_outcome']!=r['enabled_outcome']]
    payload={'schema':'local_correspondence_benchmark_v1','generated_at_utc':datetime.now(timezone.utc).isoformat(),
             'methodology':'Same 325 fixture-backed samples and unchanged S=.70, T=.70, E=.90/margin=.10. Baseline artifacts are the frozen fresh contrastive-containment v3 runs; enabled artifacts are fresh full detector runs with only the default-off local fallback enabled. Reviewed view excludes the established seven quarantined labels.',
             'summary':summary,'suites':suites,'results':all_rows}
    (ROOT/'eval/local_correspondence_benchmark.json').write_text(json.dumps(payload,indent=2),encoding='utf-8')
    print(json.dumps({'summary':summary,'suites':suites},indent=2))

if __name__=='__main__':main()
