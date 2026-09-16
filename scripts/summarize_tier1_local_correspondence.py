"""Reconstruct default-off Tier 1 verdicts from the same enabled detector runs."""
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from corpus.controller.store import load_entries
from eval.common import extract_ghsa_ids
from eval.metrics import classification_outcome
from pipeline.controller.region_detection import derive_priority
from pipeline.models.regions import RegionDetectionResult
from scripts.validate_tier1_releases import _checkpoint_key, _load, _source_fields

RESULT=ROOT/'eval/tier1_local_correspondence_target_v4_results.json'
CHECKPOINT=ROOT/'eval/tier1_local_correspondence_target_v4_results.checkpoint.json'

def priorities(findings, baseline=False):
    flagged=set();review=set();used=[]
    for finding in findings:
        detection=RegionDetectionResult.model_validate(finding['result'])
        states=[]
        for state in detection.vulnerability_states:
            if state.local_correspondence_used:
                used.append({'fix_boundary_id':state.fix_boundary_id,
                             'status':state.local_correspondence_status,
                             'methods':state.local_correspondence_methods,
                             'prior_abstention_reason':state.local_correspondence_prior_abstention_reason})
                if baseline:
                    state=state.model_copy(update={
                        'status':'uncertain',
                        'abstention_reason':state.local_correspondence_prior_abstention_reason,
                        'local_correspondence_used':False,
                    })
            states.append(state)
        priority=derive_priority(detection.lineages,states,detection.package_applicabilities) if baseline else detection.priority
        ghsas=extract_ghsa_ids(finding['result'])
        if priority=='automatic_vulnerability':flagged|=ghsas
        elif priority=='manual_review':review|=ghsas
    return flagged,review,used

def main():
    output=json.loads(RESULT.read_text())
    checkpoint=json.loads(CHECKPOINT.read_text())['completed']
    entries=load_entries()
    labels=_load(ROOT/'eval/tier1_release_labels.jsonl')
    enabled_by_identity={(r['ghsa_id'],r['kind'],r['version'],r['source_path'],r['target_source_sha256']):r for r in output['results']}
    rows=[]
    cache={}
    for label in labels:
        key=_source_fields(label,entries);checkpoint_id=_checkpoint_key(key)
        enabled=enabled_by_identity[(label['ghsa_id'],label['kind'],label['version'],key[2],key[4])]
        if enabled['outcome']=='function_absent':
            baseline_outcome='function_absent';used=[]
        else:
            if checkpoint_id not in cache:
                findings=checkpoint[checkpoint_id]['target_findings']
                ef,er,used=priorities(findings)
                bf,br,_=priorities(findings,baseline=True)
                cache[checkpoint_id]=(ef,er,bf,br,used)
            ef,er,bf,br,used=cache[checkpoint_id]
            ghsa=label['ghsa_id']
            base_priority='automatic_vulnerability' if ghsa in bf else 'manual_review' if ghsa in br else 'none'
            baseline_outcome=classification_outcome(label['expected_status'],base_priority)
        rows.append({'ghsa_id':label['ghsa_id'],'kind':label['kind'],'version':label['version'],
                     'source_language':label['source_language'],'expected_status':label['expected_status'],
                     'baseline_outcome':baseline_outcome,'enabled_outcome':enabled['outcome'],'fallback_uses':used})
    scored=[r for r in rows if r['enabled_outcome']!='function_absent']
    changed=[r for r in scored if r['baseline_outcome']!=r['enabled_outcome']]
    summary={'label_rows':len(rows),'scored_rows':len(scored),'function_absent':len(rows)-len(scored),
             'baseline':dict(Counter(r['baseline_outcome'] for r in rows)),
             'enabled':dict(Counter(r['enabled_outcome'] for r in rows)),
             'fallback_used_source_targets':sum(bool(v[4]) for v in cache.values()),
             'fallback_used_rows':sum(bool(r['fallback_uses']) for r in rows),
             'changed_rows':len(changed),
             'new_errors':[{'ghsa_id':r['ghsa_id'],'kind':r['kind'],'version':r['version'],'outcome':r['enabled_outcome']} for r in changed if r['enabled_outcome'] in {'false_positive','false_negative'}]}
    artifact={'schema':'tier1_local_correspondence_comparison_v1','generated_at_utc':datetime.now(timezone.utc).isoformat(),
              'methodology':'Default-off outcomes reconstructed by reverting only local-correspondence-used states in the exact same fresh target-function detections, then rerunning boundary-aware priority. Six unlocatable functions remain excluded in both modes.',
              'summary':summary,'changed':changed,'rows':rows}
    (ROOT/'eval/tier1_local_correspondence_comparison.json').write_text(json.dumps(artifact,indent=2),encoding='utf-8')
    print(json.dumps({'summary':summary,'changed':changed},indent=2))

if __name__=='__main__':main()
