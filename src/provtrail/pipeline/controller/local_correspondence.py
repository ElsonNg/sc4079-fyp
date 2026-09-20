"""Conservative local correspondence, experimental and fail-closed.

No execution of candidate code. Unsupported syntax or ambiguous binding abstains.
"""
from __future__ import annotations

from provtrail.pipeline.controller.region_extraction import _parse_region_source, _function_root
from provtrail.pipeline.detection.verification.edit_distance import role_tokens

class Unsupported(Exception):pass


def walk(node):
    pending=[node]
    while pending:
        current=pending.pop()
        yield current
        pending.extend(reversed(current.named_children))


def validated_root(source, filename='candidate.ts'):
    if len(source)>12000:
        raise Unsupported('source_size_limit')
    parsed=_parse_region_source(source,filename=filename)
    if parsed.tree.root_node.has_error:
        raise Unsupported('parse_error')
    root=_function_root(parsed)
    if root.type not in {'function_declaration','function_expression','method_definition','arrow_function'}:
        raise Unsupported('function_required')
    if any(c.type in {'async','*','get','set','decorator'} for c in root.children):
        raise Unsupported('async_generator_or_accessor')
    start=root.start_byte-parsed.byte_offset
    end=root.end_byte-parsed.byte_offset
    raw=source.encode()
    if start<0 or end>len(raw):
        raise Unsupported('outer_wrapper')
    if raw[:start].strip(b' \r\n\t(') or raw[end:].strip(b' \r\n\t);'):
        raise Unsupported('surrounding_code')
    nodes=list(walk(root))
    if len(nodes)>2000:
        raise Unsupported('node_limit')
    forbidden={'await_expression','yield_expression','function_declaration','function_expression','arrow_function',
               'generator_function','generator_function_declaration','class','class_declaration','class_body',
               'try_statement','switch_statement','for_statement','for_in_statement','while_statement','do_statement',
               'with_statement','labeled_statement','throw_statement','update_expression','augmented_assignment_expression'}
    for n in nodes:
        if n!=root and n.type in forbidden:
            raise Unsupported('unsupported_'+n.type)
        if n.type=='identifier' and text(n) in {'arguments','eval'}:
            raise Unsupported('dynamic_scope_or_arguments')
    params=root.child_by_field_name('parameters') or root.child_by_field_name('parameter')
    if params is None:
        raise Unsupported('parameters')
    bindings=[]
    for p in (children(params) if params.type=='formal_parameters' else [params]):
        if p.type=='required_parameter':
            if p.child_by_field_name('value') is not None:
                raise Unsupported('default_parameter')
            p=p.child_by_field_name('pattern') or children(p)[0]
        if p.type!='identifier' or text(p) in {'undefined','arguments','eval'}:
            raise Unsupported('complex_parameter')
        if text(p) in bindings:
            raise Unsupported('duplicate_parameter')
        bindings.append(text(p))
    name=root.child_by_field_name('name')
    if name is not None and any(n.type=='identifier' and n!=name and text(n)==text(name) for n in nodes):
        raise Unsupported('function_self_reference')
    body=root.child_by_field_name('body')
    for decl in [n for n in nodes if n.type=='variable_declarator']:
        var=decl.child_by_field_name('name')
        if var is None or var.type!='identifier' or text(var) in bindings or text(var)=='undefined':
            raise Unsupported('shadowing_or_complex_binding')
        if decl.parent.parent!=body:
            raise Unsupported('nested_binding_scope')
        if any(n.type=='identifier' and n!=var and text(n)==text(var) and n.start_byte<decl.end_byte for n in nodes):
            raise Unsupported('binding_used_before_initialization')
        bindings.append(text(var))
    return root


def signature(root):
    params=root.child_by_field_name('parameters') or root.child_by_field_name('parameter')
    count=len(children(params)) if params.type=='formal_parameters' else 1
    # Arrow lexical-this semantics are not assumed equivalent to normal functions.
    return ('arrow' if root.type=='arrow_function' else 'method' if root.type=='method_definition' else 'function',count)


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
    if not n.children:
        # In particular, shorthand property names must never disappear.
        return (t,text(n))
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
    root=validated_root(source)
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
    return signature(validated_root(source)),statements(nodes,env)


def order_form(source):
    nodes,env=prepare(source)
    if len(nodes)<3:raise Unsupported('too short')
    events=[];conversion=False;guard=False
    for n in nodes[:2]:
        if n.type=='if_statement':
            cond=unwrap(n.child_by_field_name('condition'));cons=block(n.child_by_field_name('consequence'))
            if cond.type!='call_expression' or text(cond.child_by_field_name('function'))!='isNil' or n.child_by_field_name('alternative') is not None:raise Unsupported('guard')
            if 'isNil' in env:raise Unsupported('shadowed_guard_helper')
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
                if expression(name,env)!=('parameter',0):raise Unsupported('non_parameter_assignment')
            if name is None or name.type!='identifier' or value is None or value.type!='call_expression' or text(value.child_by_field_name('function'))!='toLiquid':raise Unsupported('conversion')
            if 'toLiquid' in env:raise Unsupported('shadowed_conversion_helper')
            args=children(value.child_by_field_name('arguments'))
            if len(args)!=1 or expression(args[0],env)!=('parameter',0):raise Unsupported('different conversion input')
            env[text(name)]=('converted',);events.append(('convert',('parameter',0)));conversion=True
    if not conversion or not guard:raise Unsupported('missing event')
    return signature(validated_root(source)),tuple(events),statements(nodes[2:],env)


def compare_structural(v,p,c,kind):
    fn=guard_form if kind=='guard' else order_form
    try:forms=[fn(s) for s in [v,p,c]]
    except (Unsupported,RecursionError) as e:return {'status':'uncertain','reason':str(e) or 'depth_limit'}
    if forms[0]==forms[1]:return {'status':'uncertain','reason':'no distinction'}
    return {'status':'vulnerable' if forms[2]==forms[0] else 'patched' if forms[2]==forms[1] else 'uncertain','reason':'conservative whole-function correspondence'}


def returned_regex(source, filename='candidate.js'):
    try:root=validated_root(source,filename)
    except (Unsupported,RecursionError) as e:return {'reason':str(e) or 'depth_limit'}
    parsed=_parse_region_source(source,filename=filename)
    regexes=[n for n in walk(root) if n.type=='regex']
    if len(regexes)!=1:return {'reason':'requires_one_regex', 'regex_count':len(regexes)}
    regex=regexes[0]
    member=regex.parent
    if member.type!='member_expression' or member.child_by_field_name('object')!=regex:
        return {'reason':'regex_not_direct_test_receiver'}
    prop=member.child_by_field_name('property')
    call=member.parent
    if prop is None or prop.text!=b'test' or call.type!='call_expression' or call.child_by_field_name('function')!=member:
        return {'reason':'not_regex_test_call'}
    args=call.child_by_field_name('arguments').named_children
    params=root.child_by_field_name('parameters') or root.child_by_field_name('parameter')
    parameters=list(params.named_children) if params is not None and params.type=='formal_parameters' else [params] if params is not None else []
    if len(args)!=1 or args[0].type!='identifier' or any(p.type!='identifier' for p in parameters):
        return {'reason':'unsupported_argument_or_binding'}
    names=[p.text for p in parameters]
    if args[0].text not in names:return {'reason':'argument_not_function_parameter'}
    body=root.child_by_field_name('body')
    if body==call:
        flow='direct_arrow_return'
    elif body is not None and body.type=='statement_block':
        statements=[s for s in body.named_children if s.type!='comment']
        if len(statements)==1 and statements[0].type=='return_statement' and statements[0].named_children==[call]:
            flow='direct_return'
        elif len(statements)==2 and statements[0].type=='lexical_declaration' and statements[1].type=='return_statement':
            decls=statements[0].named_children
            if len(decls)!=1 or decls[0].type!='variable_declarator':return {'reason':'unsupported_temporary'}
            decl=decls[0]
            name=decl.child_by_field_name('name')
            returned=statements[1].named_children
            if decl.child_by_field_name('value')!=call or name.type!='identifier' or len(returned)!=1 or returned[0].type!='identifier' or returned[0].text!=name.text:
                return {'reason':'test_result_not_returned_unchanged'}
            if name.text in names:return {'reason':'temporary_shadows_parameter'}
            flow='temporary_then_return'
        else:return {'reason':'unsupported_control_flow'}
    else:return {'reason':'unsupported_function_body'}
    return {'regex':regex.text.decode(),'call':call.text.decode(),'argument_parameter_index':names.index(args[0].text),'signature':signature(root),
            'flow':flow,'source_start_byte':call.start_byte-parsed.byte_offset,'source_end_byte':call.end_byte-parsed.byte_offset}


def compare_regex(v,p,c,filename='candidate.js'):
    evidence={k:returned_regex(s,filename) for k,s in [('vulnerable',v),('patched',p),('candidate',c)]}
    if any('reason' in x for x in evidence.values()):return {'status':'uncertain','reason':'expression_not_supported','evidence':evidence}
    vr,pr,cr=(evidence[k] for k in ['vulnerable','patched','candidate'])
    if len({tuple(x['signature']) for x in evidence.values()})!=1:
        return {'status':'uncertain','reason':'different_function_signature','evidence':evidence}
    # Do not decide a multi-change patch from its regex alone.
    def mask(source,pattern):return ['REGEX_SLOT' if t==pattern else t for t in role_tokens(source)]
    if vr['regex']==pr['regex'] or mask(v,vr['regex'])!=mask(p,pr['regex']):
        return {'status':'uncertain','reason':'reference_not_regex_only_change','evidence':evidence}
    if len({x['argument_parameter_index'] for x in evidence.values()})!=1:
        return {'status':'uncertain','reason':'different_input_parameter','evidence':evidence}
    status='vulnerable' if cr['regex']==vr['regex'] else 'patched' if cr['regex']==pr['regex'] else 'uncertain'
    return {'status':status,'reason':'located_returned_regex' if status!='uncertain' else 'regex_matches_neither','evidence':evidence}


def decide_local_correspondence(vulnerable, patched, candidate, filename='candidate.js'):
    """Require every decisive bounded recognizer to agree on one reference side."""
    answers = {
        'regex': compare_regex(vulnerable, patched, candidate, filename),
        'guard': compare_structural(vulnerable, patched, candidate, 'guard'),
        'order': compare_structural(vulnerable, patched, candidate, 'order'),
    }
    decisive = {name: answer['status'] for name, answer in answers.items()
                if answer['status'] in {'vulnerable', 'patched'}}
    sides = set(decisive.values())
    if len(sides) == 1:
        status = next(iter(sides))
        reason = 'decisive recognizers agree'
    elif len(sides) > 1:
        status = 'uncertain'
        reason = 'local recognizers disagree'
    else:
        status = 'uncertain'
        reason = 'no bounded recognizer applies'
    return {'status': status, 'reason': reason, 'decisive': decisive, 'answers': answers}
