"""Adversarial controls and richer, advisory-disjoint correspondence checks.

This is a correspondence screen, not retrieval or end-to-end classification.
Labels for transformed own-side matches come from their original corpus side.
"""
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from corpus.controller.store import load_entries
from pipeline.controller.local_correspondence import (
    Unsupported, validated_root, walk, children, text, guard_form, order_form,
)
from pipeline.controller.region_extraction import _parse_region_source, _function_root
from scripts.check_disjoint_guard_order import sha, transform
from scripts.litmus_guard_order_static import compare as old_structural
from scripts.litmus_expression_regex import compare as old_regex
from tests.test_local_correspondence import CONTROLS, GV, GP, OV, OP, RV, RP, check


def rename(source, filename):
    try:root=validated_root(source,filename)
    except Unsupported:return None
    if any(n.type.startswith('shorthand_property') for n in walk(root)):return None
    params=root.child_by_field_name('parameters') or root.child_by_field_name('parameter')
    names=[]
    for p in (children(params) if params.type=='formal_parameters' else [params]):
        if p.type=='required_parameter':p=p.child_by_field_name('pattern') or children(p)[0]
        names.append(text(p))
    if not names:return None
    mapping={name:f'litmusInput{i}' for i,name in enumerate(names)}
    if any(name in source for name in mapping.values()):return None
    parsed=_parse_region_source(source,filename=filename)
    edits=[(n.start_byte-parsed.byte_offset,n.end_byte-parsed.byte_offset,mapping[text(n)].encode())
           for n in walk(root) if n.type=='identifier' and text(n) in mapping]
    raw=source.encode()
    for a,b,value in sorted(edits,reverse=True):raw=raw[:a]+value+raw[b:]
    return raw.decode()


def rewrite_return(source,filename,expand=False):
    parsed=_parse_region_source(source,filename=filename)
    if parsed.tree.root_node.has_error:return None
    root=_function_root(parsed);body=root.child_by_field_name('body')
    if body is None or body.type!='statement_block':return None
    nodes=children(body)
    if not nodes or nodes[-1].type!='return_statement':return None
    ret=nodes[-1];values=children(ret)
    if len(values)!=1:return None
    value=values[0]
    if expand:
        if value.type!='ternary_expression':return None
        replacement='if ('+text(value.child_by_field_name('condition'))+') { return '+text(value.child_by_field_name('consequence'))+'; } return '+text(value.child_by_field_name('alternative'))+';'
    else:
        if 'litmusResult' in source:return None
        replacement='const litmusResult = '+text(value)+'; return litmusResult;'
    a,b=ret.start_byte-parsed.byte_offset,ret.end_byte-parsed.byte_offset
    if a<0 or b>len(source.encode()):return None
    raw=source.encode()
    return (raw[:a]+replacement.encode()+raw[b:]).decode()


def forms(source):
    result={}
    for name,fn in [('guard',guard_form),('order',order_form)]:
        try:result[name]=fn(source)
        except (Unsupported,RecursionError):result[name]=None
    return result


def main():
    controls=[]
    for name,kind,candidate,expected in CONTROLS:
        new=check(kind,candidate)
        old=old_regex(RV,RP,candidate) if kind=='regex' else old_structural(GV if kind=='guard' else OV,GP if kind=='guard' else OP,candidate,kind)
        controls.append({'name':name,'kind':kind,'expected':expected,'old':old['status'],'new':new['status'],
                         'reason':new['reason'],'candidate_source':candidate})
    assert all(c['new']==c['expected'] for c in controls)
    prior=json.loads((ROOT/'eval/disjoint_guard_order_screen.json').read_text())
    keys={(r['ghsa_id'],r['fix_commit_sha'],r['vulnerable_sha256'],r['patched_sha256']) for r in prior['references']}
    entries=[];seen=set()
    for e in load_entries():
        key=(e.ghsa_id,e.fix_commit_sha,sha(e.vulnerable_function),sha(e.patched_function))
        if key in keys and key not in seen:entries.append(e);seen.add(key)
    assert seen==keys, 'Disjoint corpus changed; regenerate exclusions before continuing'
    references=[[forms(e.vulnerable_function),forms(e.patched_function)] for e in entries]
    results=[];cross=[];skips=Counter();comparisons=0
    for i,e in enumerate(entries):
        for expected,source in [('vulnerable',e.vulnerable_function),('patched',e.patched_function)]:
            renamed=rename(source,e.file_path)
            variants={'dead_branch_control':transform(source,e.file_path),
                      'parameter_rename':renamed,
                      'return_temporary':rewrite_return(source,e.file_path),
                      'ternary_to_guard':rewrite_return(source,e.file_path,True),
                      'rename_and_temporary':rewrite_return(renamed,e.file_path) if renamed else None}
            for variant,candidate in variants.items():
                if candidate is None or candidate==source:skips[variant]+=1;continue
                cf=forms(candidate)
                for j,ref in enumerate(references):
                    comparisons+=1;sides=set()
                    for kind in cf:
                        a,b=ref[0][kind],ref[1][kind]
                        if cf[kind] is None or a is None or b is None or a==b:continue
                        if cf[kind]==a:sides.add('vulnerable')
                        if cf[kind]==b:sides.add('patched')
                    decision=next(iter(sides)) if len(sides)==1 else 'uncertain'
                    row={'candidate_pair':i,'reference_pair':j,'candidate_advisory':e.ghsa_id,
                         'reference_advisory':entries[j].ghsa_id,'variant':variant,'expected':expected,'status':decision}
                    if i==j:
                        row['candidate_source']=candidate
                        results.append(row)
                    elif decision!='uncertain':
                        matched=entries[j].vulnerable_function if decision=='vulnerable' else entries[j].patched_function
                        row['original_side_source_identical']=source==matched
                        cross.append(row)
        if (i+1)%25==0:print(f'disjoint pairs {i+1}/{len(entries)}',flush=True)
    summary={'adversarial_controls':len(controls),'controls_passed':sum(c['new']==c['expected'] for c in controls),
             'prototype_unsafe_acceptances_fixed':[c['name'] for c in controls if c['old']!=c['expected'] and c['expected']=='uncertain'],
             'reference_pairs':len(entries),'advisories':len({e.ghsa_id for e in entries}),
             'candidates':len(results),'comparisons':comparisons,
             'own_wrong_side':sum(r['status'] not in {'uncertain',r['expected']} for r in results),
             'by_variant':{v:dict(Counter(r['status'] for r in results if r['variant']==v)) for v in variants},
             'cross_matches':len(cross),'cross_nonidentical_sources':sum(not r['original_side_source_identical'] for r in cross),
             'unavailable_transformations':dict(skips)}
    out={'schema':'local_correspondence_safety_v1','generated_at_utc':datetime.now(timezone.utc).isoformat(),
         'methodology':__doc__+' Uses exactly the previous disjoint screen exclusions. Unsupported transformations are counted, not forced. No Type IV proof is claimed.',
         'summary':summary,'controls':controls,'results':results,'cross_matches':cross,'references':prior['references']}
    (ROOT/'eval/local_correspondence_safety.json').write_text(json.dumps(out,indent=2),encoding='utf-8')
    print(json.dumps(summary,indent=2))


if __name__=='__main__':main()
