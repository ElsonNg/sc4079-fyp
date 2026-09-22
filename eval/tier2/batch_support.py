"""Pinned helper extraction and execution support for validation batches v6+."""
from pathlib import Path
import json
import subprocess
from eval.ablation.common import ROOT,digest,file_hash
from eval.tier2.additional_checks import assess_observations
from eval.tier2.context_checks import callable_adapter
from eval.tier2.permission_checks import observation_view
from eval.tier2.source_review import parsed

METADATA=ROOT/'eval/frozen/helper-context-v3/sources.json'
SOURCES=json.loads(METADATA.read_text(encoding='utf-8'))
SUPPORT_FILES=[Path(__file__),Path(__file__).with_name('boundary_runtime.cjs'),METADATA,
    *[ROOT/r['path'] for r in SOURCES],Path(__file__).with_name('permission_checks.py'),
    Path(__file__).with_name('context_checks.py'),Path(__file__).with_name('additional_checks.py')]


def snapshot(entry,file=None):
    record=next(r for r in SOURCES if r['repo']==entry.origin.repo and r['commit']==entry.origin.fix_commit_sha and r['file']==(file or entry.origin.file_path))
    path=ROOT/record['path']
    if file_hash(path)!=record['sha256']:raise ValueError('Helper source hash mismatch')
    text=path.read_text(encoding='utf-8')
    if file is None and entry.patched_function not in text:raise ValueError('Patched reference absent from matching snapshot')
    return text,record


def extract_declarations(text,names):
    found={}
    for node in parsed(text,'javascript').named_children:
        if node.type=='export_statement':node=node.child_by_field_name('declaration')
        if node is None:continue
        if node.type=='function_declaration':
            name=node.child_by_field_name('name').text.decode()
            if name in names:found[name]=node.text.decode()
        elif node.type in {'lexical_declaration','variable_declaration'}:
            for decl in node.named_children:
                name=decl.child_by_field_name('name')
                if name is not None and name.text.decode() in names:found[name.text.decode()]=node.text.decode()
    if set(found)!=set(names):raise ValueError('Missing helper declarations: '+str(set(names)-set(found)))
    return '\n'.join(found[name] for name in names)


def helpers(entry,names,file=None):
    text,record=snapshot(entry,file)
    code=extract_declarations(text,names)
    return code,dict(record,extracted_helpers=names,extracted_code=code,extracted_sha256=digest(code))


def execute(record,entry,script,name,scope,context='',proof=None):
    sources=[entry.vulnerable_function,entry.patched_function,record['candidate_source']]
    evidence=dict(harness=name,scope=scope,method='executable_security_boundary',reviewer_type='automated',
        source_hashes=[digest(s) for s in sources],harness_sha256=file_hash(script),supporting_context=proof or [],
        oracle='Specific security witness false on vulnerable original and true on patched original; candidate matches its labelled original across witness and controls.',
        comparison_policy='V5 comparison: normalize only local names in specified V8 TypeErrors; preserve error kinds/properties/states and raw observations.')
    try:
        adapters=[callable_adapter(s,entry.origin.source_language) for s in sources];evidence['callable_adapters']=adapters
        result=subprocess.run(['node','--max-old-space-size=128',str(script)],input=json.dumps(dict(harness=name,sources=sources,language=entry.origin.source_language,adapters=adapters,contextCode=context)),text=True,capture_output=True,timeout=15,check=True)
        evidence['execution']=json.loads(result.stdout);observations=evidence['execution']['observations']
        evidence['status']=('inconclusive_candidate_adapter' if observations[2].get('phase')=='adapter' else assess_observations(observation_view(observations),record['expected_status']))
    except (subprocess.SubprocessError,OSError,ValueError) as exc:evidence.update(status='inconclusive_execution',error=str(exc))
    return evidence
