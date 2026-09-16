"""Fresh baseline vs regex-expression fallback on all shortlisted boundaries.

Preserves original fixtures; emits reviewed fixtures with seven quarantined rows.
The retrieval corpus is held fixed to the original fixtures for fair comparison.
"""
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.litmus_localized_delta import SUITES
from scripts.litmus_expression_regex import compare, controls
from scripts.validate_llm_transformed_subset import _fixture_entries, _record_language
from pipeline.controller.region_detection import build_region_detector, RegionDetectorConfig, derive_priority
from eval.metrics import classification_outcome

QUARANTINE={**{k:'formatting-only reference; no local behavioral side distinction' for k in ['C10','C30','N-P30','N-B02']},
            **{k:'candidate addresses target fix on audited input; vulnerable-preserving label not reliable' for k in ['L070','L076','L095']}}


def main():
    controls()
    reviewed=ROOT/'eval/reviewed_verification'
    reviewed.mkdir(exist_ok=True)
    manifest=[]; results=[]
    for suite,pos,neg,_ in SUITES:
        records=[]
        for filename in [pos,neg]:
            path=ROOT/'eval'/filename
            text=path.read_text(encoding='utf-8')
            rows=[json.loads(line) for line in text.splitlines() if line.strip()]
            records.extend(rows)
            included=[r for r in rows if r['candidate_id'] not in QUARANTINE]
            (reviewed/filename).write_text(''.join(json.dumps(r)+'\n' for r in included),encoding='utf-8')
            manifest.append({'file':filename,'original_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                 'original_count':len(rows),'reviewed_count':len(included),
                 'quarantined':[{'candidate_id':r['candidate_id'],'reason':QUARANTINE[r['candidate_id']],'original_record':r} for r in rows if r['candidate_id'] in QUARANTINE]})
        (reviewed/'manifest.json').write_text(json.dumps({'policy':'Exclude from scoring only; do not relabel as patched. Original retrieval corpus retained. Original files unchanged.','files':manifest},indent=2),encoding='utf-8')
        print(f'{suite}: building original fixture corpus for {len(records)} samples',flush=True)
        detector=build_region_detector(_fixture_entries(records),config=RegionDetectorConfig(max_verification_candidates=10),save_index_artifact=False)
        for i,r in enumerate(records,1):
            language=_record_language(r)
            detection=detector.detect(r['candidate_source'],candidate_id=r['candidate_id'],language=language)
            states=list(detection.vulnerability_states); checks=[]
            # All shortlisted boundaries, not just the labelled target. Hash
            # results intentionally retain their normal deterministic shortcut.
            boundaries={detector.pairs[a.pair_id].fix_boundary_id for a in detection.aggregates}
            for boundary in sorted(boundaries):
                pair=detector.boundary_function_pairs.get(boundary)
                if pair is None:continue
                answer=compare(pair.vulnerable_region.source,pair.patched_region.source,r['candidate_source'],r['corpus_entry']['file_path'])
                index=next((n for n,s in enumerate(states) if s.fix_boundary_id==boundary),None)
                eligible=index is not None and states[index].status=='uncertain' and states[index].token_gate_passed and not states[index].boundary_rejected and not states[index].contradictions
                applied=eligible and answer['status']!='uncertain'
                if applied:
                    old=states[index]
                    states[index]=old.model_copy(update={'status':answer['status'],'abstention_reason':None,
                        'fix_evidence':old.fix_evidence+['Experimental returned-regex expression correspondence']})
                checks.append({'fix_boundary_id':boundary,'advisories':[a.ghsa_id for a in pair.advisories],
                    'eligible':eligible,'applied':applied,**answer})
            priority=derive_priority(detection.lineages,states,detection.package_applicabilities)
            before=classification_outcome(r['expected_status'],detection.priority)
            after=classification_outcome(r['expected_status'],priority)
            results.append({'candidate_id':r['candidate_id'],'suite':suite,'included_in_reviewed':r['candidate_id'] not in QUARANTINE,
                'baseline_priority':detection.priority,'regex_priority':priority,'baseline_outcome':before,'regex_outcome':after,
                'regex_checks':checks,'original_detection':detection.model_dump(mode='json')})
            if i%10==0 or i==len(records):print(f'{suite} {i}/{len(records)}; {before} -> {after}',flush=True)
        save(results,manifest)
    for m in manifest:
        assert hashlib.sha256((ROOT/'eval'/m['file']).read_bytes()).hexdigest()==m['original_sha256']
    print(json.dumps(save(results,manifest),indent=2),flush=True)


def save(results,manifest):
    summary={}
    for name,rows in [('original',results),('reviewed',[r for r in results if r['included_in_reviewed']])]:
        summary[name]={'sample_count':len(rows),'baseline':dict(Counter(r['baseline_outcome'] for r in rows)),
                      'regex_fallback':dict(Counter(r['regex_outcome'] for r in rows))}
    summary['changed']=[{k:r[k] for k in ['candidate_id','suite','baseline_outcome','regex_outcome']} for r in results if r['baseline_outcome']!=r['regex_outcome']]
    summary['checked_boundaries']=sum(len(r['regex_checks']) for r in results)
    summary['applied_boundaries']=sum(c['applied'] for r in results for c in r['regex_checks'])
    payload={'schema':'conservative_review_ablation_v1','generated_at_utc':datetime.now(timezone.utc).isoformat(),
      'methodology':'Fresh fixture-corpus pipeline baseline, then expression fallback on every shortlisted boundary with unchanged S/T/E gates and final priority recomputed. All other behavior unchanged. Reviewed scoring excludes seven quarantined rows; retrieval corpus retains original references.',
      'summary':summary,'results':results}
    (ROOT/'eval/conservative_review_ablation.json').write_text(json.dumps(payload,indent=2),encoding='utf-8')
    return summary


if __name__=='__main__':main()
