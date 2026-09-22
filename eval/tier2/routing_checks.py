"""Validation v6: path containment, window access and schema selection."""
from pathlib import Path
from eval.tier2.batch_support import SUPPORT_FILES,execute,helpers

SCRIPT=Path(__file__).with_name('routing_boundaries.cjs')
HARNESSES={('vite','viteIndexHtmlMiddleware'):'html_access',('liquidjs','lookup'):'root_lookup',
    ('liquidjs','candidates'):'fallback_candidates',('axios','isAbsoluteURL'):'absolute_url',
    ('electron','canAccessWindow'):'window_access',('fastify','validate'):'body_schema'}
SCOPES={
    'html_access':'An HTML path traversing outside preview root must not be read or sent. Node POSIX path operations are real; filesystem/send/transform/configured access are explicit stubs. Covers development allow/deny/fallback, script fetch, ended response, escaped paths and read/transform errors; no filesystem I/O.',
    'root_lookup':'Root-mode lookup must reject a candidate outside configured directories before checking existence. Drains the actual generator; contains/exists/candidates and errors are explicit filesystem-policy stubs with normal/absent/rejection controls.',
    'fallback_candidates':'With root enforcement, a fallback path outside all roots must not be yielded. Real POSIX resolution with explicit filesystem/fallback and directory-containment methods; covers relative/current file, multiple roots, disabled enforcement and missing fallback.',
    'absolute_url':'Protocol-relative //host/path must be classified as absolute. Pure extracted predicate with scheme, slash, casing and relative-path controls; no claim about full Axios request dispatch.',
    'window_access':'Stale preferences granting nodeIntegration must not authorize cross-origin access when current preferences disable it. Preference accessors and origin equality are explicit stubs; tests opener, node integration and same-origin short circuits. No Electron window is launched.',
    'body_schema':'Mixed-case Content-Type must select the configured body validator rather than skip it. Uses actual matching-fix getEssenceMediaType. Schema execution/error wrapping/async continuations are labelled stubs; covers skip flags and each validation stage, not a full schema engine.',
}
def selected(entry):return (entry.advisory.package_name,entry.origin.function_name) in HARNESSES
def check(record,entry,entries):
    if not selected(entry):return None
    name=HARNESSES[(entry.advisory.package_name,entry.origin.function_name)];context='';proof=[]
    try:
        if name=='body_schema':
            context,item=helpers(entry,['getEssenceMediaType']);proof=[item]
    except (ValueError,OSError,StopIteration) as exc:
        return dict(status='inconclusive_execution_or_context',harness=name,reviewer_type='automated',error=str(exc))
    return execute(record,entry,SCRIPT,name,SCOPES[name],context,proof)
