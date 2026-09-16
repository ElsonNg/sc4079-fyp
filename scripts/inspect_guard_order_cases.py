"""Diagnostic witnesses for selected guard/order fixtures; no classification changes.

Helpers are controlled stubs. Results demonstrate a relationship on named inputs,
not runtime equivalence or exploitability in the original package.
"""
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from pipeline.controller.parsing import parse_source


def erase_annotations(source):
    tree=parse_source(source,language='typescript')
    if tree.root_node.has_error:raise ValueError('Cannot parse selected witness source')
    spans=[]
    def visit(node):
        if node.type=='type_annotation':
            spans.append((node.start_byte,node.end_byte))
        else:
            for child in node.named_children:visit(child)
    visit(tree.root_node)
    raw=source.encode()
    for start,end in sorted(spans,reverse=True):raw=raw[:start]+raw[end:]
    return raw.decode()


JS=r"""
const vm=require('node:vm'),fs=require('node:fs');
const rows=JSON.parse(fs.readFileSync(0,'utf8')), results=[];
for(const r of rows){
 const kind=r.candidate_id.startsWith('L08')?'prototype_guard':r.candidate_id==='N-P19'?'own_property_guard':r.candidate_id==='L093'?'length_and_catch':r.candidate_id.startsWith('L06')?'callback_guard':'conversion_order';
 const scenarios=kind==='length_and_catch'?['over_length','constructor_throws']:kind==='callback_guard'?['missing_busboy','present_busboy']:['distinguishing_input'];
 for(const scenario of scenarios){
  const outcomes={};
  for(const [side,field] of [['vulnerable','vulnerable_js'],['patched','patched_js'],['candidate','candidate_js']]){
   const trace=[], queue=[], box={};let args=[];
   if(kind==='prototype_guard'){
    box.objectProto={marker:'prototype_object'};args=[{prototype:box.objectProto},'prototype'];
   }else if(kind==='own_property_guard'){
    box.AxiosError=class extends Error{};args=[{custom:'value'},Object.create({custom:123}),true];
   }else if(kind==='length_and_catch'){
    box.MAX_LENGTH=8;box.LOOSE=0;box.FULL=0;box.re=[{test(){trace.push('regex_test');return true;}}];
    box.SemVer=function(){trace.push('construct');if(scenario==='constructor_throws')throw new Error('controlled_constructor_error');this.ok=true;};
    args=[scenario==='over_length'?'123456789':'x',false];
   }else if(kind==='callback_guard'){
    box.isDone=false;box.busboy=scenario==='missing_busboy'?undefined:{removeAllListeners(){trace.push('cleanup_executes');}};
    box.req={unpipe(){trace.push('unpipe');},resume(){trace.push('resume');}};
    box.drainStream=()=>trace.push('drain');box.setImmediate=fn=>{trace.push('cleanup_scheduled');queue.push(fn);};box.next=()=>trace.push('next');args=[null];
   }else{
    box.toLiquid=()=>{trace.push('convert_to_null');return null;};
    box.isNil=x=>{trace.push('nil_check:'+String(x===null));return x==null;};
    box.isArray=()=>false;box.Drop=class{};box.isFunction=()=>false;
    box.readJSProperty=(obj)=>{trace.push('read_property');if(obj===null)throw new TypeError('controlled_null_read');return 1;};
    args=[{marker:'convertible'},'ordinary',false];
   }
   box.args=args;
   let outcome;
   try{
    const value=vm.runInNewContext('('+r[field]+')(...args)',box,{timeout:1000});
    outcome={returned:value===undefined?'undefined':value===null?'null':typeof value==='object'?'object':String(value)};
   }catch(e){outcome={threw:e.name,message:e.message};}
   // Run deferred work after the synchronous function, as a separate phase.
   for(const fn of queue){try{fn();}catch(e){outcome.deferred_throw=e.name;}}
   outcomes[side]={...outcome,trace};
  }
  results.push({candidate_id:r.candidate_id,kind,scenario,outcomes});
 }
}
process.stdout.write(JSON.stringify(results));
"""


def main():
    source=json.loads((ROOT/'eval/localized_abstention_investigation.json').read_text(encoding='utf-8'))
    ids={'L037','L038','LN021','L061','L062','L082','L083','L093','N-P19'}
    rows=[]
    for row in source['results']:
        if row['candidate_id'] not in ids:continue
        r=dict(row)
        for side in ('vulnerable','patched','candidate'):r[side+'_js']=erase_annotations(r[side+'_source'])
        rows.append(r)
    witnesses=json.loads(subprocess.run(['node','-e',JS],input=json.dumps(rows),text=True,capture_output=True,check=True).stdout)
    for witness in witnesses:
        expected='patched' if witness['candidate_id'] in {'LN021','N-P19'} else 'vulnerable'
        assert witness['outcomes']['candidate']==witness['outcomes'][expected],witness
        assert witness['outcomes']['candidate']!=witness['outcomes']['vulnerable' if expected=='patched' else 'patched'],witness
    result={'schema':'guard_order_inspection_v1','generated_at_utc':datetime.now(timezone.utc).isoformat(),
      'methodology':'Nine manually selected real fixture candidates; twelve diagnostic scenarios with controlled helpers. Only TypeScript type annotations erased via parser. No verifier decisions, thresholds, fixtures or corpus modified. Stub behavior must not be treated as proof of package behavior.',
      'summary':{'selected_candidates':len(rows),'witness_scenarios':len(witnesses),'expected_side_relationship_checks_passed':True},
      'witnesses':witnesses,
      'results':[{k:r[k] for k in ['candidate_id','expected_side','baseline_outcome','source_diff','vulnerable_source','patched_source','candidate_source']} for r in rows]}
    (ROOT/'eval/guard_order_inspection.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({'summary':result['summary'],'witnesses':witnesses},indent=2))


if __name__=='__main__':main()
