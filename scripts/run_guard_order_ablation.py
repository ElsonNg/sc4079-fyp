"""Three-way comparison on saved fresh detector outputs, all shortlisted boundaries.

Replays full detection objects from the immediately preceding fresh 325-sample
run. No retrieval/model rerun: the same shortlist and baseline evidence are held
fixed, so differences come only from the experimental fallback and aggregation.
"""
import json
import sys
from collections import Counter
from datetime import datetime,timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.litmus_localized_delta import SUITES
from scripts.validate_llm_transformed_subset import _fixture_entries
from scripts.litmus_guard_order_static import compare
from pipeline.controller.region_extraction import extract_corpus_region_pairs
from pipeline.controller.region_detection import derive_priority
from pipeline.models.regions import RegionDetectionResult
from eval.metrics import classification_outcome


def run():
    prior=json.loads((ROOT/'eval/conservative_review_ablation.json').read_text())
    records={}; functions={}
    for suite,pos,neg,_ in SUITES:
        rows=[]
        for filename in [pos,neg]:
            rows.extend(json.loads(line) for line in (ROOT/'eval'/filename).read_text(encoding='utf-8').splitlines() if line.strip())
        records.update({(suite,r['candidate_id']):r for r in rows})
        functions[suite]={p.fix_boundary_id:p for p in extract_corpus_region_pairs(_fixture_entries(rows)) if p.vulnerable_region.granularity=='function'}
    results=[]
    for old in prior['results']:
        r=records[(old['suite'],old['candidate_id'])]
        detection=RegionDetectionResult.model_validate(old['original_detection'])
        states=list(detection.vulnerability_states)
        for check in old['regex_checks']:
            if check['applied']:
                index=next(i for i,s in enumerate(states) if s.fix_boundary_id==check['fix_boundary_id'])
                states[index]=states[index].model_copy(update={'status':check['status'],'abstention_reason':None})
        regex_priority=derive_priority(detection.lineages,states,detection.package_applicabilities)
        assert regex_priority==old['regex_priority']
        checks=[]
        for original_check in old['regex_checks']:
            boundary=original_check['fix_boundary_id'];pair=functions[old['suite']][boundary]
            answers={kind:compare(pair.vulnerable_region.source,pair.patched_region.source,r['candidate_source'],kind) for kind in ['guard','order']}
            sides={a['status'] for a in answers.values() if a['status']!='uncertain'}
            index=next((i for i,s in enumerate(states) if s.fix_boundary_id==boundary),None)
            eligible=index is not None and states[index].status=='uncertain' and states[index].token_gate_passed and not states[index].boundary_rejected and not states[index].contradictions
            applied=eligible and len(sides)==1
            if applied:
                states[index]=states[index].model_copy(update={'status':next(iter(sides)),'abstention_reason':None})
            checks.append({'fix_boundary_id':boundary,'advisories':original_check['advisories'],'eligible':eligible,'applied':applied,'answers':answers})
        priority=derive_priority(detection.lineages,states,detection.package_applicabilities)
        after=classification_outcome(r['expected_status'],priority)
        results.append({'candidate_id':r['candidate_id'],'suite':old['suite'],'included_in_reviewed':old['included_in_reviewed'],
          'baseline_outcome':old['baseline_outcome'],'regex_outcome':old['regex_outcome'],'combined_outcome':after,
          'combined_priority':priority,'checks':checks})
    summary={}
    for group,rows in [('original',results),('reviewed',[r for r in results if r['included_in_reviewed']])]:
        summary[group]={'sample_count':len(rows),**{mode:dict(Counter(r[mode+'_outcome'] for r in rows)) for mode in ['baseline','regex','combined']}}
    summary['changed_from_regex']=[{k:r[k] for k in ['candidate_id','suite','regex_outcome','combined_outcome']} for r in results if r['regex_outcome']!=r['combined_outcome']]
    summary['new_errors']=[r for r in summary['changed_from_regex'] if r['combined_outcome'] in {'false_positive','false_negative'}]
    summary['boundaries_checked']=sum(len(r['checks']) for r in results)
    summary['boundaries_applied']=sum(c['applied'] for r in results for c in r['checks'])
    out={'schema':'guard_order_ablation_v1','generated_at_utc':datetime.now(timezone.utc).isoformat(),
      'methodology':__doc__,'summary':summary,'results':results}
    (ROOT/'eval/guard_order_ablation.json').write_text(json.dumps(out,indent=2),encoding='utf-8')
    print(json.dumps(summary,indent=2))


if __name__=='__main__':run()
