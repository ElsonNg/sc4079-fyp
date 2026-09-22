"""Validation v5: permission, parser and option boundaries; exact-fix helpers."""
from pathlib import Path
import json
import re
import subprocess

from eval.ablation.common import ROOT,digest,file_hash
from eval.tier2.additional_checks import assess_observations
from eval.tier2.context_checks import callable_adapter,comparison_view,extract
from eval.tier2.source_review import parsed

SCRIPT=Path(__file__).with_name('permission_boundaries.cjs')
METADATA=ROOT/'eval/frozen/helper-context-v2/sources.json'
SOURCES=json.loads(METADATA.read_text(encoding='utf-8'))
SUPPORT_FILES=[METADATA,*[ROOT/r['path'] for r in SOURCES],Path(__file__).with_name('context_checks.py'),Path(__file__).with_name('additional_checks.py')]
HARNESSES={
    ('undici','busy'):'idle_socket',
    ('vite','isFileLoadingAllowed'):'trailing_slash',
    ('fastify','getEssenceMediaType'):'media_space',
    ('parse-server','_matchesCLP'):'pointer_permission',
    ('parse-server','metadataHandler'):'metadata',
    ('electron','parseFeatures'):'window_options',
    ('minimist','setKey'):'constructor_guard',
    ('nodemailer','_normalizeAddress'):'address_controls',
}
SCOPES={
    'idle_socket':'Socket awaiting idle validation must be busy before dispatch. Exhausts socket boolean states and idle states; includes running/idempotent/upgrade/body controls. Request body classification is explicitly stubbed; no socket I/O.',
    'trailing_slash':'A denied file with a trailing slash must remain denied even when its path is otherwise allowed. Exact-equality deny and containment stubs model configured policy predicates; observes their input and ordering. No real filesystem or glob-library integration.',
    'media_space':'A space after application/json must end the MIME essence rather than remain in it. Tests casing, semicolon, whitespace, empty and malformed inputs. Pure extracted parser function; no HTTP server integration.',
    'pointer_permission':'With generic permission deferred, a pointer to another user must return false instead of allowing subscription delivery. Exercises user/read/write pointers, arrays, raw/Parse pointer objects, master/public grants and authorization failures. Schema permission and auth services are explicit stubs; tests this function\'s pointer enforcement, not full Parse authorization.',
    'metadata_auth':'Both file triggers must receive the resolved file auth instead of stale request auth. Auth resolution, triggers, file/config/error services are explicit observation stubs, including rejection and rename controls. No claim that the stub validates a real session token.',
    'metadata_error':'Missing application configuration must produce the empty HTTP 200 metadata response rather than reject outside the handler. Tests lookup rejection and metadata success/failure. Config/files/response are explicit stubs; no HTTP stack integration.',
    'window_options':'A preload option from a window.open feature string must be excluded from top-level options. Executes actual matching-fix coercion, parser and option allowlists; ordinary window options, web preferences, aliases and duplicate keys are controls. No BrowserWindow launched.',
    'constructor_guard':'Traversal through a callable constructor must not mutate its prototype. Actual matching-fix isConstructorOrProto helper, fresh VM-local objects, and ordinary/repeated/boolean/path controls. No process-global prototype is modified.',
    'address_controls':'An embedded CRLF in a mailbox local part must be removed before producing the normalized address. Uses Node\'s real punycode.toASCII, pinned by the Node version; all CTLs, angle brackets, whitespace and ordinary domain controls. No mail sent.',
}


def selected(entry):
    if (entry.advisory.package_name,entry.origin.function_name) not in HARNESSES:return False
    return entry.advisory.package_name!='minimist' or entry.origin.fix_commit_sha=='c2b981977fa834b223b408cfb860f933c9811e4d'


def observation_view(value):
    """Retain error kind/property/state, ignore local names in two V8 formats."""
    if isinstance(value,list):return [observation_view(v) for v in value]
    if not isinstance(value,dict):return value
    result={k:observation_view(v) for k,v in value.items()}
    if result.get('name')=='TypeError':
        message=result.get('error','')
        match=re.fullmatch(r"[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]* is not a function)",message)
        if match:result['error']='<local>'+match[1]
        match=re.fullmatch(r"(Cannot destructure property '[^']+' of )'[A-Za-z_$][\w$]*'( as it is (?:undefined|null)\.)",message)
        if match:result['error']=match[1]+"'<local>'"+match[2]
    return comparison_view(result)


def helper_context(entry):
    if entry.advisory.package_name not in {'electron','minimist'}:return '',[]
    record=next(r for r in SOURCES if r['repo']==entry.origin.repo and r['commit']==entry.origin.fix_commit_sha and r['file']==entry.origin.file_path)
    path=ROOT/record['path']
    if file_hash(path)!=record['sha256']:raise ValueError('Helper source hash mismatch')
    source=path.read_text(encoding='utf-8')
    if entry.patched_function not in source:raise ValueError('Patched reference absent from exact-fix helper snapshot')
    if entry.advisory.package_name=='minimist':
        names=['isConstructorOrProto'];code=extract(source,names)
    else:
        names=['keysOfTypeNumberCompileTimeCheck','keysOfTypeNumber','coerce','parseCommaSeparatedKeyValue','allowedWebPreferences','allowedWindowOptions']
        found={}
        for node in parsed(source,'typescript').named_children:
            if node.type=='export_statement':node=node.child_by_field_name('declaration')
            if node is None:continue
            if node.type=='function_declaration':
                name=node.child_by_field_name('name').text.decode()
                if name in names:found[name]=node.text.decode()
            elif node.type=='lexical_declaration':
                for decl in node.named_children:
                    n=decl.child_by_field_name('name')
                    if n is not None and n.text.decode() in names:found[n.text.decode()]=node.text.decode()
        if set(found)!=set(names):raise ValueError('Missing exact Electron helper declaration')
        code='\n'.join(found[name] for name in names)
    return code,[dict(record,extracted_helpers=names,extracted_code=code,extracted_sha256=digest(code))]


def check(record,entry,entries):
    if not selected(entry):return None
    name=HARNESSES[(entry.advisory.package_name,entry.origin.function_name)]
    if name=='metadata':name='metadata_auth' if '_resolveAuth' in entry.patched_function else 'metadata_error'
    sources=[entry.vulnerable_function,entry.patched_function,record['candidate_source']]
    evidence=dict(harness=name,scope=SCOPES[name],method='executable_security_boundary',reviewer_type='automated',
        source_hashes=[digest(s) for s in sources],harness_sha256=file_hash(SCRIPT),
        oracle='Specific witness false on vulnerable original and true on patched original; candidate must match its labelled original across witness and controls.',
        comparison_policy='Normalize captured V8 TypeError bare callee names, local receiver names for member calls, and local destructuring source names. Preserve property, null/undefined, error kind and all raw observations.')
    try:
        context,proof=helper_context(entry);evidence['supporting_context']=proof
        adapters=[callable_adapter(s,entry.origin.source_language) for s in sources]
        evidence['callable_adapters']=adapters
        payload=dict(harness=name,sources=sources,language=entry.origin.source_language,contextCode=context,adapters=adapters)
        result=subprocess.run(['node','--max-old-space-size=128',str(SCRIPT)],input=json.dumps(payload),text=True,capture_output=True,timeout=15,check=True)
        evidence['execution']=json.loads(result.stdout)
        observations=evidence['execution']['observations']
        evidence['status']=('inconclusive_candidate_adapter' if observations[2].get('phase')=='adapter'
            else assess_observations(observation_view(observations),record['expected_status']))
    except (subprocess.SubprocessError,OSError,ValueError,StopIteration) as exc:
        evidence.update(status='inconclusive_execution_or_context',error=str(exc))
    return evidence
