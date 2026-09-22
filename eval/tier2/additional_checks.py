"""A second, independent executable batch; prior validation code stays unchanged."""
from pathlib import Path
import json
import subprocess

from eval.ablation.common import digest, file_hash

SCRIPT = Path(__file__).with_name('additional_boundaries.cjs')
HARNESSES = {
    ('electron','mergeOptions'): 'electron_options',
    ('liquidjs','pop'): 'liquid_pop',
    ('liquidjs','sample'): 'liquid_sample',
    ('liquidjs','replace'): 'liquid_replace',
    ('fastify','onRead'): 'fastify_backpressure',
    ('nuxt','redirect'): 'nuxt_redirect',
    ('undici','parseURL'): 'undici_url',
    ('undici','validateCookiePath'): 'cookie_path',
    ('validator','isLength'): 'unicode_length',
    ('parse-server','RestWrite.prototype.handleSession'): 'session_fields',
    ('parse-server','requestResetPassword'): 'reset_token',
    ('parse-server','resetPassword'): 'reset_token',
    ('parse-server','verifyEmail'): 'reset_token',
    ('parse-server','calculateQueryComplexity'): 'graphql_limits',
}
SCOPES = {
    'electron_options': 'Inherited sandbox/contextIsolation defaults must populate an existing empty child webPreferences object. Includes override, nested-object, cycle and ordinary option controls. No BrowserWindow integration.',
    'liquid_pop': 'Array cloning must charge the configured memory limiter before allocation; six elements exceed a four-element stub budget. toArray uses arrays/scalars only; no Liquid object conversion integration.',
    'liquid_sample': 'Sampling one element from a six-element array must charge the whole array before copying; budget four. Deterministic Math.random; null/string/count controls and explicit identity conversion stubs.',
    'liquid_replace': 'Repeated replacements must charge output length: four a characters replaced by xxxx produce sixteen characters against budget ten. Identity/string conversion stubs; empty-pattern and ordinary controls. No heap measurement.',
    'fastify_backpressure': 'res.write(false) must register drain and stop reader.read initiation. Records call order, done/destroyed/cancel branches and non-false values. Reader is a stub returning real resolved Promises, with deterministic microtask draining; no network or memory-bound claim.',
    'nuxt_redirect': 'Meta-refresh input must use the normalized same-origin path rather than a raw //evil.test redirect. Exact same-fix patched encodeURL is used for all sources to isolate the callback change. Hook/status/HTML-escaping helpers are explicit stubs; no browser integration.',
    'undici_url': 'Object-form path=https://evil.test must not override origin=https://trusted.test. Real Node URL with path/origin/invalid-input controls. InvalidArgumentError is an Error subclass stub; no HTTP request is made.',
    'cookie_path': 'Non-ASCII U+013B must be rejected rather than allowed into a cookie path. Covers all byte-valued characters, semicolon/CTL boundaries and ordinary paths. No header serialization integration.',
    'unicode_length': 'Repeated standalone variation selectors must count toward the length bound. Tests paired selectors, surrogate pairs, discreteLengths and legacy arguments. assertString explicitly checks type.',
    'session_fields': 'A query update carrying sessionToken:null must reject the forbidden key instead of bypassing a truthiness guard. Tests four protected keys with falsy/truthy values, roles, ACL and ordinary controls. No database/session-creation integration; Parse errors are labelled stubs.',
    'reset_token': 'Object-valued token must be stringified before reaching the controller sink. Checks success/rejection, missing values, xhr, configuration and downstream stringify failures. Controller and query serialization are observation stubs; no database/email operation.',
    'graphql_limits': 'A depth-ten field chain with maxDepth=2 must stop after three counted fields rather than traverse ten. Also exercises disabled limits, field limits, repeated/cyclic fragments. Complete extracted function; no GraphQL parser or timing claim.',
}


def selected(entry):
    return (entry.advisory.package_name,entry.origin.function_name) in HARNESSES


def assess_observations(observations, side):
    """Require the intended security witness, not merely any original difference."""
    vulnerable,patched,candidate=observations
    if not vulnerable['ok'] or not patched['ok']:
        return 'inconclusive_reference_execution'
    if vulnerable['value'].get('witness') is not False or patched['value'].get('witness') is not True:
        return 'inconclusive_security_oracle'
    if not candidate['ok']:
        return 'candidate_compile_error' if candidate.get('phase')=='compile' else 'behaviour_mismatch'
    expected=vulnerable if side=='flagged' else patched
    return 'pass' if candidate['value']==expected['value'] else 'behaviour_mismatch'


def check(record,entry,entries):
    name=HARNESSES.get((entry.advisory.package_name,entry.origin.function_name))
    if name is None:
        return None
    sources=[entry.vulnerable_function,entry.patched_function,record['candidate_source']]
    payload=dict(harness=name,language=entry.origin.source_language,sources=sources)
    evidence=dict(harness=name,scope=SCOPES[name],harness_sha256=file_hash(SCRIPT),
        source_hashes=[digest(s) for s in sources],supporting_context=[],
        method='executable_security_boundary',reviewer_type='automated',
        oracle='Security witness must be false on the original vulnerable source and true on the original patched source; candidate must match its side across the witness and all controls.')
    if name=='nuxt_redirect':
        matches=[e for e in entries if e.advisory.package_name=='nuxt' and e.origin.function_name=='encodeURL'
            and e.origin.fix_commit_sha==entry.origin.fix_commit_sha]
        if not matches or len({e.patched_function for e in matches})!=1:
            return dict(evidence,status='inconclusive_missing_matching_helper')
        helper=matches[0]
        payload['helper']=dict(source=helper.patched_function,language=helper.origin.source_language)
        evidence['supporting_context']=[helper.model_dump()]
    try:
        result=subprocess.run(['node','--max-old-space-size=128',str(SCRIPT)],input=json.dumps(payload),
            text=True,capture_output=True,timeout=12,check=True)
        evidence['execution']=json.loads(result.stdout)
        evidence['status']=assess_observations(evidence['execution']['observations'],record['expected_status'])
    except (subprocess.SubprocessError,OSError,ValueError) as exc:
        evidence.update(status='inconclusive_execution',error=str(exc))
    return evidence
