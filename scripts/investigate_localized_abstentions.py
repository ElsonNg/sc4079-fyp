"""Read-only investigation of saved localized-delta misses; writes audit artifacts.

No detector, thresholds or fixture labels are changed. Node witnesses execute
only three explicitly selected local fixture functions in a timed VM with stubs.
"""
import difflib
import json
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from pipeline.controller.edit_distance import role_tokens

GROUPS = {
    'receiver_identity_erased': {'C05','C06','C27','N-P05','N-P06','N-P27'},
    'reference_formatting_only': {'C10','C30','N-P30','N-B02'},
    'template_literal_and_context': {'L055','L059','L063','LN031','LN032','LN034'},
    'temporary_variable_breaks_context': {'C13','N-P13'},
}

WITNESS_JS = r"""
const fs=require('node:fs'), vm=require('node:vm');
const rows=JSON.parse(fs.readFileSync(0,'utf8'));
const results=[];
for(const row of rows){
 const observations={};
 for(const [side, field] of [['vulnerable','vulnerable_source'],['patched','patched_source'],['candidate','candidate_source']]){
  const source=row[field];
  const sandbox={};
  let expression;
  if(row.candidate_id==='L095'){
   expression='('+source+')({}, "__proto__")';
  }else{
   sandbox.req={method:'GET',headers:{'sec-websocket-key':'dGhlIHNhbXBsZSBub25jZQ==','sec-websocket-version':'13'}};
   sandbox.socket={on(){}};
   sandbox.socketOnError=()=>{};
   sandbox.keyRegex={test:()=>true};
   sandbox.abortHandshake=()=> 'rejected_without_exception';
   expression='({'+source+'}).handleUpgrade.call({shouldHandle(){return true},options:{}}, req, socket, null, null)';
  }
  try{observations[side]={returned:vm.runInNewContext(expression,sandbox,{timeout:1000})};}
  catch(error){observations[side]={threw:error.name,message:error.message};}
 }
 results.push({candidate_id:row.candidate_id,
  input:row.candidate_id==='L095'?'obj={}, key=__proto__':'GET request with upgrade header absent; other handshake inputs stubbed valid',
  observations});
}
process.stdout.write(JSON.stringify(results));
"""


def main():
    data=json.loads((ROOT/'eval/localized_delta_litmus.json').read_text(encoding='utf-8'))
    rows=[r for r in data['results'] if 'baseline_outcome' in r]
    selected=[r for r in rows if r['eligible_saved_gate']]
    annotated=[]
    for r in selected:
        category=next((k for k, ids in GROUPS.items() if r['candidate_id'] in ids),'added_deleted_reordered_or_multiedit')
        annotated.append({**r, 'investigation_group':category,
            'source_diff': ''.join(difflib.unified_diff(r['vulnerable_source'].splitlines(True),r['patched_source'].splitlines(True),fromfile='vulnerable',tofile='patched')),
            'role_tokens_identical':role_tokens(r['vulnerable_source'])==role_tokens(r['patched_source']),
            'prototype_blockers':dict(Counter(x.get('reason','resolved') for x in r['localized']['changes']))})
    witnesses=json.loads(subprocess.run(['node','-e',WITNESS_JS],input=json.dumps([r for r in rows if r['candidate_id'] in {'L095','L076','L070'}]),text=True,capture_output=True,check=True).stdout)
    for witness in witnesses:
        obs=witness['observations']
        assert obs['candidate']==obs['patched'], witness
        assert obs['candidate']!=obs['vulnerable'], witness
    review=[r for r in rows if r['baseline_outcome'].startswith('abstained')]
    def review_group(r):
        states=r['saved_target_states']
        if not states:return 'no_saved_target_state'
        if any(s['status']=='patched' for s in states):return 'target_already_patched_other_boundaries_remain'
        if r['eligible_saved_gate']:return 'target_uncertain_after_ST'
        return 'target_uncertain_before_ST'
    summary={'baseline_review_samples':len(review),
        'baseline_review_groups':dict(Counter(review_group(r) for r in review)),
        'eligible_target_boundary_records':len(selected),
        'eligible_sample_outcomes':dict(Counter(r['baseline_outcome'] for r in selected)),
        'primary_groups':dict(Counter(r['investigation_group'] for r in annotated)),
        'group_ids':{k:[r['candidate_id'] for r in annotated if r['investigation_group']==k] for k in sorted({r['investigation_group'] for r in annotated})},
        'label_review_witnesses':witnesses}
    result={'schema':'localized_abstention_investigation_v1','generated_at_utc':datetime.now(timezone.utc).isoformat(),
        'methodology':'Diagnoses saved target-boundary misses, no pipeline rerun or relabeling. Primary groups are manual source-inspection categories, not classifier outputs. Witnesses demonstrate behavior for one selected input, not universal semantic equivalence. Negative fixture sides retain previous litmus convention (patched/benign).',
        'summary':summary,'results':annotated}
    (ROOT/'eval/localized_abstention_investigation.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(summary,indent=2))


if __name__=='__main__':
    main()
