"""Validation v7: cookie header boundaries and proxy credential handling."""
from pathlib import Path
from eval.tier2.batch_support import SUPPORT_FILES as BASE_SUPPORT_FILES,helpers,snapshot
from eval.tier2.batch_support_v2 import execute
from eval.tier2.source_review import parsed

SCRIPT=Path(__file__).with_name('header_boundaries.cjs')
SUPPORT_FILES=[*BASE_SUPPORT_FILES,Path(__file__).with_name('batch_support_v2.py')]
HARNESSES={('undici','validateCookieDomain'):'cookie_domain',('undici','stringify'):'cookie_attributes',('axios','setProxy'):'proxy'}
SCOPES={
    'cookie_domain':'A CRLF-containing cookie domain must reject. Uses the actual same-fix character predicate, with all byte-valued interior characters, label/total-length boundaries and ordinary domain controls. Pure validator; no network I/O.',
    'cookie_attributes':'A CRLF-containing unparsed cookie attribute must reject before a header string is returned. All supporting cookie validators and date formatting are extracted from the matching fix and held fixed across originals/candidate to isolate stringify. Includes all byte-valued key/value characters, prefixes, flags, dates, normal attributes and failures.',
    'proxy_bypass':'An environment proxy must be bypassed for a trailing-dot hostname matching NO_PROXY after normalization. Uses real matching-fix shouldBypassProxy and real Node URL/Buffer. Environment proxy lookup is an explicit stub exercising the branch where it returns a proxy; controls include explicit proxy overrides, auth forms, bypass patterns and redirects. No external proxy library or HTTP integration.',
    'proxy_redirect':'Redirecting away from a proxy must remove every case variant of stale Proxy-Authorization while preserving initial user headers. Executes the installed redirect callback and real same-fix bypass helper. Proxy environment lookup is explicitly stubbed, URL/Buffer are real, and controls include replacement credentials and explicit proxies. No network I/O.',
}

def selected(entry):return (entry.advisory.package_name,entry.origin.function_name) in HARNESSES

def check(record,entry,entries):
    if not selected(entry):return None
    name=HARNESSES[(entry.advisory.package_name,entry.origin.function_name)]
    try:
        if name=='cookie_domain':context,proof=helpers(entry,['isLetterOrDigit'])
        elif name=='cookie_attributes':
            context,proof=helpers(entry,['isCTLExcludingHtab','validateCookieName','validateCookieValue','validateCookiePath','isLetterOrDigit','validateCookieDomain','IMFDays','IMFMonths','IMFPaddedNumbers','toIMFDate','validateCookieMaxAge'])
        else:
            _,primary=snapshot(entry)
            text,aux=snapshot(entry,'lib/helpers/shouldBypassProxy.js')
            names=[]
            for node in parsed(text,'javascript').named_children:
                if node.type=='export_statement':node=node.child_by_field_name('declaration')
                if node is None:continue
                if node.type=='function_declaration':names.append(node.child_by_field_name('name').text.decode())
                elif node.type=='lexical_declaration':
                    names.extend(n.child_by_field_name('name').text.decode() for n in node.named_children if n.child_by_field_name('name') is not None)
            context,proof=helpers(entry,names,'lib/helpers/shouldBypassProxy.js')
            proof=[primary,proof]
            name='proxy_redirect' if 'isRedirect' in entry.patched_function else 'proxy_bypass'
        if not isinstance(proof,list):proof=[proof]
    except (OSError,ValueError,StopIteration) as exc:
        return dict(status='inconclusive_execution_or_context',harness=name,reviewer_type='automated',error=str(exc))
    return execute(record,entry,SCRIPT,name,SCOPES[name],context,proof)
