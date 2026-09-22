"""V7 execution provider: explicit UTF-8 transport for Unicode observations."""
import json
import subprocess
from eval.ablation.common import digest,file_hash
from eval.tier2.additional_checks import assess_observations
from eval.tier2.context_checks import callable_adapter
from eval.tier2.permission_checks import observation_view


def execute(record,entry,script,name,scope,context='',proof=None):
    sources=[entry.vulnerable_function,entry.patched_function,record['candidate_source']]
    evidence=dict(harness=name,scope=scope,method='executable_security_boundary',reviewer_type='automated',
        source_hashes=[digest(s) for s in sources],harness_sha256=file_hash(script),supporting_context=proof or [],
        oracle='Specific security witness false on vulnerable original and true on patched original; candidate matches its labelled original across witness and controls.',
        comparison_policy='V5 comparison: normalize only local names in specified V8 TypeErrors; preserve error kinds/properties/states and raw observations.')
    try:
        adapters=[callable_adapter(s,entry.origin.source_language) for s in sources];evidence['callable_adapters']=adapters
        result=subprocess.run(['node','--max-old-space-size=128',str(script)],input=json.dumps(dict(harness=name,sources=sources,language=entry.origin.source_language,adapters=adapters,contextCode=context)),text=True,encoding='utf-8',capture_output=True,timeout=15,check=True)
        evidence['execution']=json.loads(result.stdout);observations=evidence['execution']['observations']
        evidence['status']=('inconclusive_candidate_adapter' if observations[2].get('phase')=='adapter' else assess_observations(observation_view(observations),record['expected_status']))
    except (subprocess.SubprocessError,OSError,ValueError) as exc:evidence.update(status='inconclusive_execution',error=str(exc))
    return evidence
