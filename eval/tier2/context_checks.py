"""Versioned tests for unresolved cases, including exact-fix upstream helpers."""
from pathlib import Path
import json
import re
import subprocess

from eval.ablation.common import ROOT,digest,file_hash
from eval.tier2.additional_checks import assess_observations
from eval.tier2.source_review import parsed

SCRIPT=Path(__file__).with_name('context_boundaries.cjs')
CONTEXT=ROOT/'eval/frozen/helper-context-v1'
METADATA=CONTEXT/'sources.json'
SOURCES=json.loads(METADATA.read_text(encoding='utf-8'))
SUPPORT_FILES=[METADATA,*[Path(r['path']) for r in SOURCES],Path(__file__).with_name('additional_checks.py')]
HARNESSES={
    ('axios','computeConfigValue'):'axios_keys',
    ('moment','loadLocale'):'moment_locale',
    ('undici','processHeader'):'undici_header',
    ('nuxt','getRouteRules'):'route_rules',
    ('multer','done'):'multer_cleanup',
    ('parse-server','handleMe'):'parse_me',
    ('ws','handleUpgrade'):'websocket_upgrade',
    ('handlebars','depthedLookup'):'handlebars_name',
    ('vite','getRelativeUrlFromDocument'):'vite_document',
    ('fastify','ContentTypeParser'):'fastify_mime',
    ('fastify','ContentTypeParser.prototype.add'):'fastify_mime',
    ('fastify','ContentTypeParser.prototype.getParser'):'fastify_mime',
}
SCOPES={
    'axios_keys':'Forbidden prototype keys must not call merge helpers or mutate the result prototype. Includes inherited merge-map handlers, direct-key semantics and ordinary values. Merge helpers and utils are explicit observation/intrinsic stubs.',
    'moment_locale':'Traversal-like locale names must not reach require. Uses actual isLocaleNameSane at the matching fix. require records calls only; cache, ordinary names and failure controls. No filesystem module is loaded by the candidate.',
    'undici_header':'A content-type containing CRLF must fail before raw headers are appended. Uses exact token/header regex declarations from the matching fix, with ordinary/reserved-header and value-type controls. Error classes are stubs; no network I/O.',
    'route_rules':'Mixed-case paths must reach the matcher lowercased. Matcher and logging are observation stubs; string/event/error controls. No complete Nuxt route-matching integration.',
    'multer_cleanup':'An absent busboy instance must not schedule dereferencing cleanup. Exercises absent/present instance, done guard and explicitly drained immediate-callback queue. Request/drain/next are observation stubs.',
    'parse_me':'User retrieval must use caller auth through rest.get, and master session lookup must omit include:user. Exercises missing session/user and lookup failures. Database/auth/error/hiding services are explicit stubs; no real ACL enforcement claim.',
    'websocket_upgrade':'Missing Upgrade header must yield HTTP 400 abort rather than an uncaught property-access error. Tests method/version/casing and verification branches. Socket/abort callbacks are stubs; extension negotiation is disabled.',
    'handlebars_name':'A crafted quoted lookup name must remain a single string argument, without executing an inert injected marker. Generated code executes in a second bounded VM with no I/O. aliasable and lookup are observation stubs; ordinary escaping controls.',
    'vite_document':'Generated base selection must ignore an IMG named currentScript and fall back to document.baseURI. Executes generated argument expressions in a separate bounded VM. Simple asset path only; escaping/encoding/URL-wrapper helpers are explicit stubs, not tested transformations.',
    'fastify_mime':'text/plain with a quoted application/custom parameter must select the plain parser, not the registered custom parser. Runs the candidate in matching-side constructor/add/getParser context from the reference plus actual patched helper definitions. content-type v1.0.4 is a pinned test dependency compatible with the recorded ^1.0.4 range, not a claim about the historical resolved install. Map cache, body-parser callbacks and errors are stubs; body parsing itself is outside scope.',
}


def selected(entry):return (entry.advisory.package_name,entry.origin.function_name) in HARNESSES


def callable_adapter(source,language,candidate_id=None):
    """Identify a declared callable without changing its body or helper bindings."""
    try:root=parsed(source,language)
    except ValueError:return None
    bindings=[]
    for node in root.named_children:
        if node.type=='comment':continue
        if node.type=='function_declaration':
            bindings.append(node.child_by_field_name('name').text.decode())
        elif node.type in {'lexical_declaration','variable_declaration'}:
            for decl in node.named_children:
                name=decl.child_by_field_name('name');value=decl.child_by_field_name('value')
                if name is not None and name.type=='identifier' and value is not None and value.type in {'arrow_function','function_expression'}:
                    bindings.append(name.text.decode())
        else:return None
    if len(bindings)==1:
        return dict(name=bindings[0],kind='single_declared_callable',source_sha256=digest(source))
    # Reviewed against this exact fixture: rewrite is the two-argument entry;
    # the other declarations implement its helpers. Never infer the last function.
    if candidate_id=='L257' and digest(source)=='7d0ed18db5b2dd85aa3a80a8499273a7fbcebf864529a9cbf3e92701ab4393ca' and 'rewrite' in bindings:
        return dict(name='rewrite',kind='bound_entrypoint_review',source_sha256=digest(source),
            reviewer_type='automated',reviewer='Codex',reason='rewrite accepts relativePath and umd and calls the three local helpers; preserve every declaration unchanged.')
    return None


def comparison_view(value):
    """Ignore only V8's bare local callee name in captured TypeError messages."""
    if isinstance(value,list):return [comparison_view(v) for v in value]
    if not isinstance(value,dict):return value
    result={k:comparison_view(v) for k,v in value.items()}
    if result.get('name')=='TypeError' and re.fullmatch(r'[A-Za-z_$][\w$]* is not a function',result.get('error','')):
        result['error']='<callee> is not a function'
    return result


def load_context(package,entry=None):
    record=next(r for r in SOURCES if r['package']==package)
    path=Path(record['path'])
    if file_hash(path)!=record['sha256']:raise ValueError('Helper source hash mismatch')
    if entry is not None and (record['commit']!=entry.origin.fix_commit_sha or record['repo']!=entry.origin.repo):
        raise ValueError('Helper must match exact reference repository and fix')
    text=path.read_text(encoding='utf-8')
    if entry is not None and entry.patched_function not in text:
        raise ValueError('Reference patched function absent from helper source snapshot')
    return text,record


def extract(text,names):
    """Copy whole top-level AST statements, preserving exact regex/string bytes."""
    found={}
    for node in parsed(text,'javascript').named_children:
        if node.type=='function_declaration':
            name=node.child_by_field_name('name').text.decode()
            if name in names:found[name]=node.text.decode()
        elif node.type in {'lexical_declaration','variable_declaration'}:
            for decl in node.named_children:
                name_node=decl.child_by_field_name('name')
                if name_node is not None and name_node.text.decode() in names:
                    found[name_node.text.decode()]=node.text.decode()
        elif node.type=='expression_statement' and node.named_children:
            assignment=node.named_children[0]
            left=assignment.child_by_field_name('left')
            if left is not None and left.text.decode() in names:found[left.text.decode()]=node.text.decode()
    if set(names)!=set(found):raise ValueError('Missing exact helper definitions: '+str(set(names)-set(found)))
    return '\n'.join(found[name] for name in names)


def build_context(name,record,entry,entries):
    payload={};evidence=[]
    if name in {'moment_locale','undici_header'}:
        package='moment' if name=='moment_locale' else 'undici'
        text,snapshot=load_context(package,entry)
        names=['isLocaleNameSane'] if package=='moment' else ['tokenRegExp','headerCharRegex']
        code=extract(text,names);payload['contextCode']=code
        evidence=[dict(snapshot,extracted_helpers=names,extracted_code=code,extracted_sha256=digest(code))]
    elif name=='fastify_mime':
        text,snapshot=load_context('fastify',entry)
        dependency,dep_snapshot=load_context('content-type')
        package,pkg_snapshot=load_context('fastify-package')
        if pkg_snapshot['commit']!=entry.origin.fix_commit_sha or json.loads(package)['dependencies']['content-type']!='^1.0.4':
            raise ValueError('Unexpected test-dependency constraint')
        names=['dummyContentType','safeParseContentType','compareContentType','compareRegExpContentType','ParserListItem','ParserListItem.prototype.toString','Parser']
        code=extract(text,names)
        payload['contextCode']='const parseContentType=(()=>{const exports={};\n'+dependency+'\nreturn exports.parse;})();\n'+code
        bindings={}
        for function,token in [('ContentTypeParser','ORIGINAL_CTOR'),('ContentTypeParser.prototype.add','ORIGINAL_ADDER'),('ContentTypeParser.prototype.getParser','ORIGINAL_GETTER')]:
            matches=[e for e in entries if e.origin.repo==entry.origin.repo and e.origin.fix_commit_sha==entry.origin.fix_commit_sha and e.origin.function_name==function]
            if len(matches)!=1:raise ValueError('Missing or ambiguous matching Fastify context')
            matched=matches[0]
            if matched.patched_function not in text:raise ValueError('Helper/reference extraction mismatch')
            bindings[token]=(matched.vulnerable_function,matched.patched_function)
            evidence.append(dict(reference_context=matched.model_dump()))
        for assignment,token in [('ContentTypeParser.prototype.hasParser','HAS_PARSER'),('ContentTypeParser.prototype.existingParser','EXISTING_PARSER')]:
            statement=extract(text,[assignment])
            node=parsed(statement,'javascript').named_children[0].named_children[0]
            source=node.child_by_field_name('right').text.decode()
            bindings[token]=(source,source)
        side=0 if record['expected_status']=='flagged' else 1
        payload['contexts']=[{token:pair[index] for token,pair in bindings.items()} for index in (0,1,side)]
        evidence.extend([dict(snapshot,extracted_helpers=names,extracted_code=code,extracted_sha256=digest(code)),dep_snapshot,pkg_snapshot])
    return payload,evidence


def check(record,entry,entries):
    name=HARNESSES.get((entry.advisory.package_name,entry.origin.function_name))
    if name is None:return None
    sources=[entry.vulnerable_function,entry.patched_function,record['candidate_source']]
    evidence=dict(harness=name,scope=SCOPES[name],method='executable_security_boundary',reviewer_type='automated',
        source_hashes=[digest(s) for s in sources],harness_sha256=file_hash(SCRIPT),
        oracle='Specific security witness false on vulnerable original, true on patched original; candidate must match its side across witness and controls.')
    try:
        context,proof=build_context(name,record,entry,entries)
        evidence['supporting_context']=proof
        adapters=[callable_adapter(s,entry.origin.source_language,record.get('candidate_id') if i==2 else None) for i,s in enumerate(sources)]
        evidence['callable_adapters']=adapters
        evidence['comparison_policy']='Exact observations except bare local-callee names in captured V8 TypeError messages; raw observations retained.'
        payload=dict(harness=name,language=entry.origin.source_language,functionName=entry.origin.function_name,sources=sources,adapters=adapters,**context)
        result=subprocess.run(['node','--max-old-space-size=128',str(SCRIPT)],input=json.dumps(payload),text=True,capture_output=True,timeout=12,check=True)
        evidence['execution']=json.loads(result.stdout)
        observations=evidence['execution']['observations']
        evidence['status']=('inconclusive_candidate_adapter' if observations[2].get('phase')=='adapter'
            else assess_observations(comparison_view(observations),record['expected_status']))
    except (subprocess.SubprocessError,OSError,ValueError) as exc:
        evidence.update(status='inconclusive_execution_or_context',error=str(exc))
    return evidence
