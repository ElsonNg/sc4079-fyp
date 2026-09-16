"""Conservative whole-function correspondence for guard and synchronous-order litmus.

Alpha-renames simple parameters/locals; preserves operators, calls, properties and
literal values. Supports explicit, small return/temporary rewrites only. Not a
production verifier; unsupported constructs abstain.
"""
import json
import sys
from collections import Counter
from pathlib import Path
from datetime import datetime, timezone

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from pipeline.controller.region_extraction import _parse_region_source,_function_root


class Unsupported(Exception):pass


def children(n):return [c for c in n.named_children if c.type!='comment']
def text(n):return n.text.decode() if n is not None else ''
def unwrap(n):
    while n is not None and n.type=='parenthesized_expression':n=children(n)[0]
    return n


def expression(n,env):
    n=unwrap(n)
    if n is None:return ('undefined',)
    t=n.type
    if t=='identifier':return env.get(text(n),('external',text(n)))
    if t=='undefined':return ('undefined',)
    if t in {'string','number','true','false','null','regex','property_identifier'}:return (t,text(n))
    if t in {'arrow_function','function_expression','await_expression','yield_expression','update_expression','assignment_expression'}:raise Unsupported(t)
    return (t,tuple(expression(c,env) if c.is_named else ('syntax',text(c)) for c in n.children if c.type!='comment'))


def block(n):return children(n) if n is not None and n.type=='statement_block' else [n] if n else []


def statements(nodes,env):
    nodes=[n for n in nodes if n.type!='comment']
    if not nodes:return ('end',)
    n,*rest=nodes
    if n.type=='return_statement':
        if rest:raise Unsupported('unreachable trailing statements')
        cs=children(n);value=unwrap(cs[0]) if cs else None
        if value is not None and value.type=='ternary_expression':
            return ('if',expression(value.child_by_field_name('condition'),env),
                ('return',expression(value.child_by_field_name('consequence'),env)),
                ('return',expression(value.child_by_field_name('alternative'),env)))
        return ('return',expression(value,env))
    if n.type=='if_statement':
        condition=unwrap(n.child_by_field_name('condition'))
        consequence=block(n.child_by_field_name('consequence'))
        alternative=n.child_by_field_name('alternative')
        if alternative is not None and alternative.type=='else_clause':alternative=children(alternative)[0]
        # Only discard the exact no-op inserted by deterministic fixtures.
        if condition.type=='false' and alternative is None and len(consequence)==1 and text(consequence[0]).strip()=='void 0;':
            return statements(rest,env)
        # Safe continuation folding only when the branch itself returns.
        if consequence and consequence[-1].type=='return_statement':
            return ('if',expression(condition,env),statements(consequence,dict(env)),statements(block(alternative)+rest,dict(env)))
        return ('if_then',expression(condition,env),statements(consequence,dict(env)),statements(block(alternative),dict(env)),statements(rest,env))
    if n.type in {'lexical_declaration','variable_declaration'}:
        decls=children(n)
        if len(decls)!=1:raise Unsupported('multiple declarations')
        decl=decls[0];name=decl.child_by_field_name('name');value=decl.child_by_field_name('value')
        if name is None or name.type!='identifier' or value is None or text(name) in env:raise Unsupported('shadowing or unsupported declaration')
        # An immediate return of the newly bound value evaluates it exactly once.
        if len(rest)==1 and rest[0].type=='return_statement' and len(children(rest[0]))==1 and text(children(rest[0])[0])==text(name):
            return ('return',expression(value,env))
        val=expression(value,env)
        symbol=('local',sum(1 for binding in env.values() if binding[0]=='local'))
        env=dict(env);env[text(name)]=symbol
        return ('bind',symbol,val,statements(rest,env))
    if n.type in {'for_statement','while_statement'}:
        # Loop-local names and updates are intentionally unsupported in v1.
        raise Unsupported('loop')
    if n.type in {'try_statement','switch_statement','function_declaration'}:raise Unsupported(n.type)
    return (n.type,tuple(expression(c,env) for c in children(n)),statements(rest,env))


def prepare(source):
    parsed=_parse_region_source(source,filename='candidate.ts')
    if parsed.tree.root_node.has_error:raise Unsupported('parse error')
    root=_function_root(parsed)
    params=root.child_by_field_name('parameters')
    if params is None:raise Unsupported('parameters')
    env={}
    for i,p in enumerate(children(params)):
        if p.type=='required_parameter':p=p.child_by_field_name('pattern') or children(p)[0]
        if p.type!='identifier':raise Unsupported('complex parameter')
        env[text(p)]=('parameter',i)
    body=root.child_by_field_name('body')
    if body is None or body.type!='statement_block':raise Unsupported('body')
    return block(body),env


def guard_form(source):
    nodes,env=prepare(source)
    return statements(nodes,env)


def order_form(source):
    nodes,env=prepare(source)
    if len(nodes)<3:raise Unsupported('too short')
    events=[];conversion=False;guard=False
    for n in nodes[:2]:
        if n.type=='if_statement':
            cond=unwrap(n.child_by_field_name('condition'));cons=block(n.child_by_field_name('consequence'))
            if cond.type!='call_expression' or text(cond.child_by_field_name('function'))!='isNil' or n.child_by_field_name('alternative') is not None:raise Unsupported('guard')
            args=children(cond.child_by_field_name('arguments'))
            if len(args)!=1 or len(cons)!=1 or cons[0].type!='return_statement' or len(children(cons[0]))!=1:raise Unsupported('guard return')
            arg=expression(args[0],env)
            if expression(children(cons[0])[0],env)!=arg:raise Unsupported('different returned value')
            required=('converted',) if conversion else ('parameter',0)
            if arg!=required:raise Unsupported('wrong guarded value')
            events.append(('nil_guard',arg));guard=True
        else:
            value=None;name=None
            if n.type in {'lexical_declaration','variable_declaration'} and len(children(n))==1:
                d=children(n)[0];name=d.child_by_field_name('name');value=d.child_by_field_name('value')
                if text(name) in env:raise Unsupported('shadowing')
            elif n.type=='expression_statement' and len(children(n))==1 and children(n)[0].type=='assignment_expression':
                d=children(n)[0]
                if text(d.child_by_field_name('operator')) not in {'','='}:raise Unsupported('assignment operator')
                name=d.child_by_field_name('left');value=d.child_by_field_name('right')
            if name is None or name.type!='identifier' or value is None or value.type!='call_expression' or text(value.child_by_field_name('function'))!='toLiquid':raise Unsupported('conversion')
            args=children(value.child_by_field_name('arguments'))
            if len(args)!=1 or expression(args[0],env)!=('parameter',0):raise Unsupported('different conversion input')
            env[text(name)]=('converted',);events.append(('convert',('parameter',0)));conversion=True
    if not conversion or not guard:raise Unsupported('missing event')
    return tuple(events),statements(nodes[2:],env)


def compare(v,p,c,kind):
    fn=guard_form if kind=='guard' else order_form
    try:forms=[fn(s) for s in [v,p,c]]
    except Unsupported as e:return {'status':'uncertain','reason':str(e)}
    if forms[0]==forms[1]:return {'status':'uncertain','reason':'no distinction'}
    return {'status':'vulnerable' if forms[2]==forms[0] else 'patched' if forms[2]==forms[1] else 'uncertain','reason':'conservative whole-function correspondence'}


def main():
    rows=json.loads((ROOT/'eval/localized_abstention_investigation.json').read_text())['results']
    ids={'L082':'guard','L083':'guard','N-P19':'guard','L037':'order','L038':'order','LN021':'order'}
    results=[]
    for r in rows:
        if r['candidate_id'] in ids:
            kind=ids[r['candidate_id']]
            results.append({'candidate_id':r['candidate_id'],'kind':kind,'expected_side':r['expected_side'],**compare(r['vulnerable_source'],r['patched_source'],r['candidate_source'],kind)})
    guard_v='function get(obj,key){return obj[key];}'
    guard_p='function get(obj,key){if(key === "blocked") return undefined; return obj[key];}'
    order_v='function read(obj,key){if(isNil(obj)) return obj; obj=toLiquid(obj); return readJSProperty(obj,key);}'
    order_p='function read(obj,key){obj=toLiquid(obj); if(isNil(obj)) return obj; return readJSProperty(obj,key);}'
    controls=[
      ('guard_v',guard_v,'guard','vulnerable'),('guard_p',guard_p,'guard','patched'),
      ('wrong_guarded_input','function get(obj,key){if(obj === "blocked") return undefined; return obj[key];}','guard','uncertain'),
      ('wrong_lookup','function get(obj,key){if(key === "blocked") return undefined; return other[key];}','guard','uncertain'),
      ('late_guard','function get(obj,key){const x=obj[key]; if(key === "blocked") return undefined; return x;}','guard','uncertain'),
      ('ignored_guard','function get(obj,key){key === "blocked"; return obj[key];}','guard','uncertain'),
      ('alternate_path','function get(obj,key){if(flag) return obj[key]; if(key === "blocked") return undefined; return obj[key];}','guard','uncertain'),
      ('changed_operator','function get(obj,key){if(key == "blocked") return undefined; return obj[key];}','guard','uncertain'),
      ('order_v',order_v,'order','vulnerable'),('order_p',order_p,'order','patched'),
      ('order_alias','function read(input,key){const value=toLiquid(input); if(isNil(value)) return value; return readJSProperty(value,key);}','order','patched'),
      ('wrong_order_input','function read(obj,key){obj=toLiquid(key); if(isNil(obj)) return obj; return readJSProperty(obj,key);}','order','uncertain'),
      ('stale_checked_value','function read(obj,key){const value=toLiquid(obj); if(isNil(obj)) return obj; return readJSProperty(value,key);}','order','uncertain'),
      ('mutation','function read(obj,key){obj=toLiquid(obj); obj=other; if(isNil(obj)) return obj; return readJSProperty(obj,key);}','order','uncertain'),
      ('async','function read(obj,key){setImmediate(()=>toLiquid(obj)); if(isNil(obj)) return obj; return readJSProperty(obj,key);}','order','uncertain'),
    ]
    checked=[]
    for name,c,kind,expected in controls:
        answer=compare(guard_v if kind=='guard' else order_v,guard_p if kind=='guard' else order_p,c,kind)
        assert answer['status']==expected,(name,answer)
        checked.append({'candidate_id':name,'expected':expected,'candidate_source':c,**answer})
    out={'schema':'guard_order_static_litmus_v1','generated_at_utc':datetime.now(timezone.utc).isoformat(),
      'methodology':'Narrow whole-function AST correspondence, no threshold changes or production integration. Operators and unknown inputs remain distinct. Loops and async unsupported.',
      'summary':{'real_cases':len(results),'controls_passed':len(checked),'status_counts':dict(Counter(r['status'] for r in results))},'results':results,'controls':checked}
    (ROOT/'eval/guard_order_static_litmus.json').write_text(json.dumps(out,indent=2))
    print(json.dumps(out,indent=2))


if __name__=='__main__':main()
