"""Isolated regex-expression localization and reference-quality audit.

No production or benchmark-label mutations. Runs against saved fixture inputs.
"""
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from pipeline.controller.region_extraction import _parse_region_source, _function_root
from pipeline.controller.edit_distance import role_tokens
from scripts.litmus_localized_delta import SUITES


def walk(node):
    yield node
    for child in node.named_children:
        yield from walk(child)


def canonical(node):
    """Audit syntax, preserving identifiers, operators and literal contents.

    Ignore comments and delimiter tokens represented by the surrounding AST.
    Normalize only the optional parentheses around one arrow parameter.
    This is an audit representation, not a proposed production fingerprint.
    """
    if node.type=='comment': return None
    if node.type=='formal_parameters' and len(node.named_children)==1 and node.named_children[0].type=='identifier':
        return canonical(node.named_children[0])
    if not node.children or node.type in {'string','regex','template_string'}:
        return (node.type,node.text.decode())
    children=[canonical(c) for c in node.children if c.type not in {'(',')','{','}',',',';'}]
    return (node.type,tuple(c for c in children if c is not None))


def returned_regex(source, filename='candidate.js'):
    parsed=_parse_region_source(source,filename=filename)
    if parsed.tree.root_node.has_error:return {'reason':'parse_error'}
    root=_function_root(parsed)
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
    return {'regex':regex.text.decode(),'call':call.text.decode(),'argument_parameter_index':names.index(args[0].text),
            'flow':flow,'source_start_byte':call.start_byte-parsed.byte_offset,'source_end_byte':call.end_byte-parsed.byte_offset}


def compare(v,p,c,filename='candidate.js'):
    evidence={k:returned_regex(s,filename) for k,s in [('vulnerable',v),('patched',p),('candidate',c)]}
    if any('reason' in x for x in evidence.values()):return {'status':'uncertain','reason':'expression_not_supported','evidence':evidence}
    vr,pr,cr=(evidence[k] for k in ['vulnerable','patched','candidate'])
    # Do not decide a multi-change patch from its regex alone.
    def mask(source,pattern):return ['REGEX_SLOT' if t==pattern else t for t in role_tokens(source)]
    if vr['regex']==pr['regex'] or mask(v,vr['regex'])!=mask(p,pr['regex']):
        return {'status':'uncertain','reason':'reference_not_regex_only_change','evidence':evidence}
    if len({x['argument_parameter_index'] for x in evidence.values()})!=1:
        return {'status':'uncertain','reason':'different_input_parameter','evidence':evidence}
    status='vulnerable' if cr['regex']==vr['regex'] else 'patched' if cr['regex']==pr['regex'] else 'uncertain'
    return {'status':status,'reason':'located_returned_regex' if status!='uncertain' else 'regex_matches_neither','evidence':evidence}


def controls():
    v='function probe(url, other) { return /^https:/.test(url); }'
    p='function probe(url, other) { return /^https?:/.test(url); }'
    variants={
        'vulnerable_temporary':('function probe(input, other) { const result = /^https:/.test(input); return result; }','vulnerable'),
        'patched_temporary':('function probe(input, other) { const result = /^https?:/.test(input); return result; }','patched'),
        'third_regex':('function probe(input, other) { return /^ftp:/.test(input); }','uncertain'),
        'wrong_input':('function probe(input, other) { return /^https?:/.test(other); }','uncertain'),
        'wrong_method':('function probe(input, other) { return /^https?:/.exec(input); }','uncertain'),
        'unused_result':('function probe(input, other) { const result = /^https?:/.test(input); return other; }','uncertain'),
        'mutated_result':('function probe(input, other) { let result = /^https?:/.test(input); result = true; return result; }','uncertain'),
        'dead_branch':('function probe(input, other) { if (false) return /^https?:/.test(input); return false; }','uncertain'),
        'two_regexes':('function probe(input, other) { return /^https?:/.test(input) || /^https:/.test(input); }','uncertain'),
        'nested_function':('function probe(input, other) { function inner() {return /^https?:/.test(input);} return false; }','uncertain'),
        'inverted_result':('function probe(input, other) { return !/^https?:/.test(input); }','uncertain'),
    }
    result=[]
    for name,(c,expected) in variants.items():
        actual=compare(v,p,c)
        assert actual['status']==expected,(name,actual)
        result.append({'candidate_id':name,'expected':expected,'candidate_source':c,**actual})
    return result


def main():
    prior=json.loads((ROOT/'eval/localized_delta_litmus.json').read_text(encoding='utf-8'))
    rows=[r for r in prior['results'] if 'baseline_outcome' in r]
    filenames={}
    for suite, positive, negative, _ in SUITES:
        for source_file in (positive,negative):
            for line in (ROOT/'eval'/source_file).read_text(encoding='utf-8').splitlines():
                if line.strip():
                    record=json.loads(line)
                    filenames[(suite,record['candidate_id'])]=record['corpus_entry']['file_path']
    output=[]
    for r in rows:
        filename=filenames[(r['suite'],r['candidate_id'])]
        result=compare(r['vulnerable_source'],r['patched_source'],r['candidate_source'],filename)
        proposal=result['status'] if r['eligible_saved_gate'] and result['status']!='uncertain' else None
        output.append({**r,'expression_result':result,'expression_boundary_proposal':proposal})
    proposals=[r for r in output if r['expression_boundary_proposal']]
    audits=[]
    for r in rows:
        if r['candidate_id'] not in {'C10','C30','N-P30','N-B02'}:continue
        v=_parse_region_source(r['vulnerable_source']);p=_parse_region_source(r['patched_source'])
        equal=not v.tree.root_node.has_error and not p.tree.root_node.has_error and canonical(_function_root(v))==canonical(_function_root(p))
        assert equal,r['candidate_id']
        audits.append({'candidate_id':r['candidate_id'],'syntax_equal_after_delimiter_comment_normalization':equal,
                       'proposed_action':'exclude from local vulnerable-versus-patched verification scoring; retain provenance separately',
                       'applied':False})
    checks=controls()
    summary={'sample_count':len(rows),'control_count':len(checks),'control_checks_passed':True,
      'expression_status_counts':dict(Counter(r['expression_result']['status'] for r in output)),
      'new_target_boundary_proposals':[{k:r[k] for k in ['candidate_id','baseline_outcome','expected_side','expression_boundary_proposal']} for r in proposals],
      'proposals_disagreeing_with_labels':sum(r['expression_boundary_proposal']!=r['expected_side'] for r in proposals),
      'formatting_reference_audit':audits,
      'label_audit_reference':'localized_abstention_investigation.json: label_review_witnesses; no label edits applied',
      'proposed_label_actions':[
          {'candidate_id':identifier,'action':'quarantine from vulnerable-preserving transformation scores pending target-specific relabel review',
           'reason':'candidate matches patched behavior on the audited fix-triggering input','applied':False}
          for identifier in ['L076','L095','L070']
      ]}
    payload={'schema':'expression_regex_litmus_v1','generated_at_utc':datetime.now(timezone.utc).isoformat(),
      'methodology':'Known-reference expression checks on saved 325 fixtures, reusing prior target S/T eligibility. Direct regex.test(parameter) returned directly or via one unchanged temporary. No retrieval or full aggregation rerun. Side attribution is exact regex matching, not a proof of global safety.',
      'summary':summary,'controls':checks,'results':output}
    (ROOT/'eval/expression_regex_litmus.json').write_text(json.dumps(payload,indent=2),encoding='utf-8')
    print(json.dumps(summary,indent=2))


if __name__=='__main__':main()
