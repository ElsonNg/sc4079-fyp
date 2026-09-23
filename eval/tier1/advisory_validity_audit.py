"""Audit Tier 1 advisory/source identity without requiring exploit execution."""
from __future__ import annotations

from collections import Counter
import difflib
import hashlib
import json
from pathlib import Path

from eval.ablation.common import digest, entry_identity, identity
from eval.common import DEFAULT_SNAPSHOT_DB
from eval.tier2.extend_validation_v3 import build_records, read_jsonl
from provtrail.corpus.integrations.sqlite_store import load_entries
from provtrail.pipeline.controller.parsing import extract_function_units

ROOT=Path(__file__).resolve().parents[2]
PREVIOUS=ROOT/'eval/frozen/revalidation-v43/validation.jsonl'
OUTPUT=ROOT/'eval/frozen/tier1-advisory-audit-v1'
SCOPES=(
    ('revalidation-v34','line_review_100_scope.json'),
    ('revalidation-v35','line_review_100b_scope.json'),
    ('revalidation-v36-corrected','line_review_100c_scope.json'),
    ('revalidation-v37','line_review_100d_scope.json'),
    ('revalidation-v38','line_review_remaining_scope.json'),
)
RELEASE_PAIR_MARKERS={
    'GHSA-m983-v2ff-wq65':('object: deletedParseObject,','object: localDeletedParseObject,'),
    'GHSA-fmh4-wcc4-5jm3':('ctx.context.orgOptions.requireEmailVerificationOnInvitation &&',
                           '(ctx.context.orgOptions.requireEmailVerificationOnInvitation ?? true) &&'),
    'GHSA-fph2-r4qg-9576':('await this._matchesCLP(',
                           'const matchesCLP = await this._matchesCLP('),
    'GHSA-8xwg-wv7v-4vqp':('getWebPreferences().nativeWindowOpen',
                           'getLastWebPreferences().nativeWindowOpen'),
}
WS_RELEASE_FILES={
    '1.1.4':'917e8e0c99128059214ca7000521d37ab14bfb1ec490f55f8622310ce52d6a15',
    '1.1.5':'d40fc5fdae0297d667a9cece64438869409f10f3074603c585a8f37308db71d2',
    '3.3.0':'a662d66258af859d29e29cf59c00d3fd8a0a19796922e6d009d5731575575bc5',
    '3.3.1':'2014c1f5668530347da992685356cc3f951a428aa09fae287e78ebb3eacd82ad',
}


def line_reviews():
    found={}
    for report,scope_name in SCOPES:
        scope=json.loads((ROOT/'eval/tier2'/scope_name).read_text(encoding='utf8'))
        for case in scope['cases']:
            found[case['candidate_id']]=f'eval/frozen/{report}/line-review.md'
    return found


def audit():
    entries=load_entries(DEFAULT_SNAPSHOT_DB)
    by_origin={entry_identity(e):e for e in entries}
    prior={r['candidate_id']:r for r in read_jsonl(PREVIOUS)}
    reviews=line_reviews()
    records=[r for r in build_records(entries) if r['tier']=='tier1']
    assert len(records)==600 and len(prior)==1388
    historical={}
    for ghsa,markers in RELEASE_PAIR_MARKERS.items():
        group=[r for r in records if r['ghsa_id']==ghsa and
               prior[r['candidate_id']]['status']=='reference_source_mismatch' and r.get('candidate_source')]
        assert group and {r['expected_status'] for r in group}=={'flagged','cleared'}
        for r in group:
            assert digest(r['candidate_source'])==r['target_source_sha256']
            expected_marker=markers[0 if r['expected_status']=='flagged' else 1]
            assert expected_marker in r['candidate_source']
            assert markers[1] in by_origin[identity(r)].patch_hunk
        historical[ghsa]=group
    ws_sources={}
    for record in records:
        if record['ghsa_id']!='GHSA-5v72-xg48-5rpm' or prior[record['candidate_id']]['status']!='reference_source_mismatch':
            continue
        path=ROOT/'eval/tier1/reference_sources'/f"ws-{record['version']}-Extensions.js"
        data=path.read_bytes()
        assert hashlib.sha256(data).hexdigest()==WS_RELEASE_FILES[record['version']]
        source=data.decode('utf8')
        matched=[unit for unit in extract_function_units(source,filename='Extensions.js')
                 if digest(unit.source)==record['target_source_sha256']]
        assert len(matched)==1 and matched[0].name is None
        assert record['source_repo']=='websockets/ws' and record['corpus_file_path']=='lib/Extensions.js'
        marker=('extensions[token] = extensions[token] || []' if record['expected_status']=='flagged'
                else '!extensions.hasOwnProperty(token)')
        assert marker in matched[0].source
        ws_sources[record['candidate_id']]=dict(source=matched[0].source,
            file=str(path.relative_to(ROOT)).replace('\\','/'),file_sha256=WS_RELEASE_FILES[record['version']],
            url=f"https://raw.githubusercontent.com/{record['source_repo']}/{record['source_commit']}/{record['corpus_file_path']}")
    assert len(ws_sources)==4
    rows=[]
    for record in records:
        cid=record['candidate_id']
        entry=by_origin[identity(record)]
        old=prior[cid]
        side='vulnerable' if record['expected_status']=='flagged' else 'patched'
        source=getattr(entry,side+'_function')
        actual=digest(source)
        target=record['target_source_sha256']
        exact=target==actual and not record.get('unavailable_source')
        checks={
            'advisory_id':record['ghsa_id']==entry.advisory.ghsa_id==identity(record)[0],
            'package':record['package_name']==entry.advisory.package_name,
            'repository':record['source_repo']==entry.origin.repo,
            'file_path':record['corpus_file_path']==entry.origin.file_path,
            'language':record['source_language']==entry.origin.source_language,
            'fix_commit_cited':any(entry.origin.fix_commit_sha in ref for ref in entry.advisory.advisory_references),
            'nonempty_reference_change':entry.vulnerable_function!=entry.patched_function and bool(entry.patch_hunk),
            'version_side':record['version'] in entry.advisory.fixed_versions if side=='patched' else
                record['version'] not in entry.advisory.fixed_versions,
            'source_digest':exact,
        }
        if not all(value for key,value in checks.items() if key!='source_digest'):
            verdict='metadata_conflict'
        elif old['status'].startswith('excluded_'):
            verdict='excluded_security_label'
        elif not exact and record['ghsa_id'] in historical:
            verdict='valid_release_specific_reference'
        elif not exact and record['ghsa_id']=='GHSA-fjgf-rc76-4x9p':
            assert digest(record['candidate_source'])==target
            assert ('function (err) {' if side=='vulnerable' else
                    'function (err, includeFile) {') in record['candidate_source']
            verdict='excluded_incompatible_release_pair'
        elif not exact and cid in ws_sources:
            verdict='valid_release_specific_reference'
        elif not exact:
            raise AssertionError('Unreviewed release source mismatch: '+cid)
        else:
            verdict='valid_advisory_reference'
        line_evidence=old.get('executable_evidence') or {}
        if old['status']=='needs_review':
            assert exact and cid in reviews
            assert line_evidence.get('source_hashes')==[
                digest(entry.vulnerable_function),digest(entry.patched_function),actual]
            assert len(line_evidence.get('numbered_sources',[]))==3
        rows.append(dict(candidate_id=cid,verdict=verdict,previous_validation_status=old['status'],
            advisory_id=record['ghsa_id'],advisory_url=entry.advisory.advisory_url,
            advisory_title=entry.advisory.advisory_title,package=record['package_name'],
            version=record['version'],reference_side=side,
            listed_fixed_versions=entry.advisory.fixed_versions,
            origin=list(identity(record)),fix_commit=entry.origin.fix_commit_sha,
            fix_commit_reference=next(ref for ref in entry.advisory.advisory_references
                                      if entry.origin.fix_commit_sha in ref),
            release_source_commit=record.get('source_commit'),
            release_tarball_sha256=record.get('expected_sha256'),
            target_source_sha256=target,current_reference_sha256=actual,
            historical_release_source_sha256=(digest(record['candidate_source']) if record.get('candidate_source')
                                             else digest(ws_sources[cid]['source']) if cid in ws_sources else None),
            historical_release_file=ws_sources[cid]['file'] if cid in ws_sources else None,
            historical_release_file_sha256=ws_sources[cid]['file_sha256'] if cid in ws_sources else None,
            historical_release_url=ws_sources[cid]['url'] if cid in ws_sources else None,
            checks=checks,line_review=reviews.get(cid),
            limitation=('The historical release snippet differs from the fix-commit extraction but its hash matches the release target and the advisory-specific before/after line change is present. No exploitability claim.'
                if verdict=='valid_release_specific_reference' else
                'The release snippets are different callbacks with incompatible signatures; this is not a coherent labelled source pair.'
                if verdict=='excluded_incompatible_release_pair' else
                'The exact patch artifact is not a standalone security-labelled pair; see prior exclusion reason.'
                if verdict=='excluded_security_label' else
                'Advisory/source identity only; no exploitability or full-package behavior claim.')))
    return rows,entries


def main():
    rows,entries=audit()
    OUTPUT.mkdir(parents=True,exist_ok=True)
    (OUTPUT/'cases.jsonl').write_text(''.join(json.dumps(row,ensure_ascii=False)+'\n' for row in rows),encoding='utf8')
    counts=Counter(row['verdict'] for row in rows)
    assert counts=={'valid_advisory_reference':532,'valid_release_specific_reference':16,
                    'excluded_security_label':50,'excluded_incompatible_release_pair':2}
    assert sum(row['checks']['source_digest'] for row in rows)==582
    assert sum(row['reference_side']=='patched' for row in rows)==300
    assert sum(row['previous_validation_status']=='needs_review' for row in rows
               if row['verdict']=='valid_advisory_reference')==178
    summary=dict(total=600,verdicts=dict(counts),exact_reference_sources=582,
        fixed_versions_matching_advisory=300,vulnerable_versions_not_listed_as_fixed=300,
        advisory_commit_references=600,previously_pending_now_advisory_valid=178,
        valid_advisory_sources=548,excluded_as_security_sources=52,
        security_exclusions_retained=50,source_mismatches_unverified=0,
        source='frozen local advisory/release-label/corpus snapshots plus four pinned ws release files',
        previous_validation=str(PREVIOUS.relative_to(ROOT)))
    (OUTPUT/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf8')
    mismatches=[r for r in rows if not r['checks']['source_digest']]
    lines=['# Tier 1 release-source mismatches','',
           'All 18 release target hashes differ from the fix-commit function. Sixteen have hash-bound historical release source with the advisory-specific before/after change; two Multer callbacks are incompatible.','',
           '| Candidate | Package/version | Side | Advisory | Verdict | Target hash | Reference hash |',
           '|---|---|---|---|---|---|---|']
    for row in mismatches:
        lines.append(f"| {row['candidate_id']} | {row['package']} {row['version']} | {row['reference_side']} | {row['advisory_id']} | {row['verdict']} | `{row['target_source_sha256'][:12]}` | `{row['current_reference_sha256'][:12]}` |")
    (OUTPUT/'mismatches.md').write_text('\n'.join(lines)+'\n',encoding='utf8')
    pair_lines=['# Historical release-specific source pairs','',
                'Each historical snippet matches its Tier 1 target hash. These are release-source comparisons; no exploit is executed.','']
    mismatch_ids={r['candidate_id'] for r in mismatches}
    for ghsa in sorted(RELEASE_PAIR_MARKERS):
        group=[r for r in build_records(entries) if r['candidate_id'] in mismatch_ids and
               r['ghsa_id']==ghsa and r.get('candidate_source')]
        vulnerable=next(r['candidate_source'] for r in group if r['expected_status']=='flagged')
        patched=next(r['candidate_source'] for r in group if r['expected_status']=='cleared')
        pair_lines += [f'## {ghsa}', '', '```diff',
            *difflib.unified_diff(vulnerable.splitlines(),patched.splitlines(),lineterm=''),
            '```', '']
    (OUTPUT/'release-specific-diffs.md').write_text('\n'.join(pair_lines)+'\n',encoding='utf8')
    ws_pair_lines=['# ws historical release source pairs','',
                   'The four source files were fetched from immutable release commits and are hash-pinned in the audit script. The anonymous callback in each file matches the labelled Tier 1 target hash.','']
    by_id={r['candidate_id']:r for r in mismatches}
    for old_version,new_version in (('1.1.4','1.1.5'),('3.3.0','3.3.1')):
        vulnerable=next(r for r in mismatches if r['package']=='ws' and r['version']==old_version)
        patched=next(r for r in mismatches if r['package']=='ws' and r['version']==new_version)
        old_source=next(unit.source for unit in extract_function_units(
            (ROOT/vulnerable['historical_release_file']).read_text(encoding='utf8'),filename='Extensions.js')
            if digest(unit.source)==vulnerable['target_source_sha256'])
        new_source=next(unit.source for unit in extract_function_units(
            (ROOT/patched['historical_release_file']).read_text(encoding='utf8'),filename='Extensions.js')
            if digest(unit.source)==patched['target_source_sha256'])
        ws_pair_lines += [f'## {old_version} → {new_version}', '',
            f"Source: {vulnerable['historical_release_url']} and {patched['historical_release_url']}",'',
            '```diff',*difflib.unified_diff(old_source.splitlines(),new_source.splitlines(),lineterm=''),
            '```','']
    (OUTPUT/'ws-release-diffs.md').write_text('\n'.join(ws_pair_lines)+'\n',encoding='utf8')
    # One complete vulnerable/patched line diff per distinct still-pending Tier 1 origin.
    old={r['candidate_id']:r for r in read_jsonl(PREVIOUS)}
    pending_origins={tuple(r['origin']) for r in rows if old[r['candidate_id']]['status']=='needs_review'}
    by_origin={entry_identity(e):e for e in entries}
    diffs=[]
    for origin in sorted(pending_origins,key=str):
        entry=by_origin[origin]
        diffs.append(dict(origin=list(origin),advisory_title=entry.advisory.advisory_title,
            advisory_url=entry.advisory.advisory_url,
            vulnerable_sha256=digest(entry.vulnerable_function),patched_sha256=digest(entry.patched_function),
            patch_hunk_sha256=digest(entry.patch_hunk),
            changed_lines=list(difflib.unified_diff(entry.vulnerable_function.splitlines(),
                entry.patched_function.splitlines(),lineterm=''))))
    (OUTPUT/'origin-line-diffs.jsonl').write_text(''.join(json.dumps(x,ensure_ascii=False)+'\n' for x in diffs),encoding='utf8')
    assert len(diffs)==len(pending_origins)
    names=('cases.jsonl','summary.json','mismatches.md','origin-line-diffs.jsonl',
           'release-specific-diffs.md','ws-release-diffs.md')
    names+=tuple(f'eval/tier1/reference_sources/ws-{version}-Extensions.js' for version in WS_RELEASE_FILES)
    (OUTPUT/'lock.json').write_text(json.dumps({name:hashlib.sha256((OUTPUT/name).read_bytes()).hexdigest()
                                               if not name.startswith('eval/') else
                                               hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
                                               for name in names},indent=2)+'\n',encoding='utf8')
    print(json.dumps({**summary,'pending_origins_line_diffed':len(diffs)},indent=2))


if __name__=='__main__':main()
