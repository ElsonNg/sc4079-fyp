"""Different-advisory correspondence screen, not a full detection benchmark.

Frozen guard/order rules are exercised against both transformed sides and wrong
reference pairs. Excludes shared advisories, fix commits and source snapshots.
"""
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from datetime import datetime,timezone

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from corpus.controller.store import load_entries
from scripts.litmus_localized_delta import SUITES
from scripts.litmus_guard_order_static import guard_form,order_form,Unsupported
from pipeline.controller.region_extraction import _parse_region_source,_function_root


def sha(s):return hashlib.sha256(s.encode()).hexdigest()


def transform(source,filename):
    parsed=_parse_region_source(source,filename=filename)
    if parsed.tree.root_node.has_error:return None
    root=_function_root(parsed);body=root.child_by_field_name('body')
    if body is None or body.type!='statement_block':return None
    raw=source.encode();pos=body.start_byte+1-parsed.byte_offset
    if pos<0 or pos>len(raw):return None
    # Same bounded no-op supported by the frozen recognizer; no scope changes.
    return (raw[:pos]+b'\nif (false) { void 0; }\n'+raw[pos:]).decode()


def forms(s):
    out={}
    for name,fn in [('guard',guard_form),('order',order_form)]:
        try:out[name]=fn(s)
        except (Unsupported,RecursionError):out[name]=None
    return out


def main():
    fixtures=[json.loads(line) for _,p,n,_ in SUITES for name in [p,n] for line in (ROOT/'eval'/name).read_text(encoding='utf-8').splitlines() if line.strip()]
    advisories={r['corpus_entry']['ghsa_id'] for r in fixtures}
    commits={r['corpus_entry']['fix_commit_sha'] for r in fixtures}
    hashes={sha(r[k]) for r in fixtures for k in ['vulnerable_function','patched_function']}
    selected=[];seen=set();skips=Counter()
    for e in load_entries():
        aliases={e.ghsa_id}|{a.get('ghsa_id') for a in e.advisory_aliases}
        if aliases & advisories or e.fix_commit_sha in commits or any(sha(s) in hashes for s in [e.vulnerable_function,e.patched_function]):
            skips['overlap']+=1;continue
        if not e.vulnerable_function or not e.patched_function or max(len(e.vulnerable_function),len(e.patched_function))>8000:
            skips['empty_or_over_8000_chars']+=1;continue
        key=(sha(e.vulnerable_function),sha(e.patched_function))
        if key in seen:skips['duplicate_pair']+=1;continue
        seen.add(key)
        candidates=[transform(s,e.file_path) for s in [e.vulnerable_function,e.patched_function]]
        if any(c is None for c in candidates):skips['no_supported_outer_block']+=1;continue
        selected.append((e,[forms(e.vulnerable_function),forms(e.patched_function)],[(c,forms(c)) for c in candidates]))
    own=[];cross=[];total=0
    for i,(entry,reference,candidates) in enumerate(selected):
        for expected,(candidate,cf) in zip(['vulnerable','patched'],candidates):
            for j,(other,ref,_) in enumerate(selected):
                total+=1;sides=set()
                for kind in ['guard','order']:
                    a,b=ref[0][kind],ref[1][kind]
                    if a is None or b is None or cf[kind] is None or a==b:continue
                    if cf[kind]==a:sides.add('vulnerable')
                    elif cf[kind]==b:sides.add('patched')
                decision=next(iter(sides)) if len(sides)==1 else 'uncertain'
                row={'candidate_advisory':entry.ghsa_id,'reference_advisory':other.ghsa_id,'expected_side':expected,'status':decision,'function':entry.function_name,
                     'candidate_pair_index':i,'reference_pair_index':j}
                if i==j:own.append(row)
                elif decision!='uncertain':
                    original_source=entry.vulnerable_function if expected=='vulnerable' else entry.patched_function
                    matched_source=other.vulnerable_function if decision=='vulnerable' else other.patched_function
                    row['original_side_source_identical']=original_source==matched_source
                    cross.append(row)
    summary={'reference_pairs':len(selected),'advisories':len({e.ghsa_id for e,_,_ in selected}),
      'candidate_count':len(own),'all_comparisons':total,'own_status_counts':dict(Counter(r['status'] for r in own)),
      'own_wrong_side':sum(r['status'] not in {'uncertain',r['expected_side']} for r in own),
      'cross_reference_matches':len(cross),'skips':dict(skips)}
    payload={'schema':'disjoint_guard_order_screen_v1','generated_at_utc':datetime.now(timezone.utc).isoformat(),
      'methodology':__doc__+' Candidates use a dead-branch insertion, not broad semantic rewrites. No retrieval/S/T gates or final detection priorities. Cross-reference matches require manual attribution review and are not automatically false positives.',
      'summary':summary,'results':own,'cross_matches':cross,
      'references':[{'ghsa_id':e.ghsa_id,'fix_commit_sha':e.fix_commit_sha,'file_path':e.file_path,'vulnerable_sha256':sha(e.vulnerable_function),'patched_sha256':sha(e.patched_function)} for e,_,_ in selected]}
    (ROOT/'eval/disjoint_guard_order_screen.json').write_text(json.dumps(payload,indent=2),encoding='utf-8')
    print(json.dumps(summary,indent=2))


if __name__=='__main__':main()
