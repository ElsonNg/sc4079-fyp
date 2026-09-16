"""Isolated, conservative patch-delta experiment; no production changes.

Localize each replacement with unchanged token flanks, then check the exact
changed tokens at that location. Require every change to resolve to one side.
Insertions/deletions and ambiguous locations deliberately abstain in this v1.
Run: .venv/Scripts/python.exe scripts/litmus_localized_delta.py
"""
from __future__ import annotations

import difflib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from corpus.controller.extraction import compute_diagnostic_lines
from corpus.models.corpus import CorpusEntry
from pipeline.controller.edit_distance import role_tokens, score_edit_distance, anchor_has_identity
from pipeline.controller.region_extraction import enumerate_candidate_regions, extract_vulnerability_regions
from pipeline.controller.region_verification import classify_boundary, verify_region_pair
from pipeline.controller.provenance import fix_boundary_id


def localized_delta(vulnerable, patched, candidate):
    v, p, c = map(role_tokens, (vulnerable, patched, candidate))
    ops = difflib.SequenceMatcher(a=v, b=p, autojunk=False).get_opcodes()
    details = []
    for index, (tag, i, j, a, b) in enumerate(ops):
        if tag == 'equal':
            continue
        detail = {'kind': tag, 'vulnerable_tokens': v[i:j], 'patched_tokens': p[a:b]}
        details.append(detail)
        if tag != 'replace':
            detail['reason'] = 'insertion_or_deletion_not_supported'
            continue
        before = ops[index - 1] if index else None
        after = ops[index + 1] if index + 1 < len(ops) else None
        left = v[max(before[1], i - 16):i] if before and before[0] == 'equal' else []
        right = v[j:min(after[2], j + 16)] if after and after[0] == 'equal' else []
        detail.update(left_context=left, right_context=right)
        if len(left) < 3 or len(right) < 3:
            detail['reason'] = 'insufficient_shared_context'
            continue
        # Enumerate candidate locations using both unchanged flanks. No best-side
        # tie breaking: multiple corresponding locations must remain unresolved.
        candidate_widths = sorted({j - i, b - a})
        # Shrink context when an insertion outside the expression breaks a wide
        # window. Pool all admissible locations: selecting only the longest
        # context can hide another occurrence containing the opposite side.
        locations = []
        options = sorted(((l+r,l,r) for l in range(3,len(left)+1) for r in range(3,len(right)+1)), reverse=True)
        used_contexts = []
        for size, lwidth, rwidth in options:
            lctx, rctx = left[-lwidth:], right[:rwidth]
            if not anchor_has_identity(lctx+rctx):
                continue
            found = []
            for start in range(len(lctx), len(c)):
                if c[start-len(lctx):start] != lctx:
                    continue
                for width in candidate_widths:
                    end = start + width
                    if c[end:end+len(rctx)] == rctx:
                        actual = c[start:end]
                        side = 'vulnerable' if actual == v[i:j] else 'patched' if actual == p[a:b] else 'neither'
                        found.append({'start_token': start, 'end_token': end, 'actual': actual, 'side': side})
            if found:
                used_contexts.append({'left':lctx,'right':rctx})
                locations.extend(found)
        locations = list({(x['start_token'],x['end_token']):x for x in locations}.values())
        detail['selected_contexts'] = used_contexts
        detail['locations'] = locations
        if len(locations) != 1:
            detail['reason'] = 'no_location' if not locations else 'multiple_locations'
        elif locations[0]['side'] == 'neither':
            detail['reason'] = 'changed_part_matches_neither'
        else:
            detail['side'] = locations[0]['side']
    sides = {d.get('side') for d in details}
    side = next(iter(sides)) if details and len(sides) == 1 and None not in sides else 'uncertain'
    return {'status': side, 'reason': 'all_changes_match_one_side' if side != 'uncertain' else 'no_distinguishing_change' if not details else 'unresolved_or_mixed_changes', 'changes': details}


def entry_for(v, p, name='probe'):
    return CorpusEntry(ghsa_id='litmus-localized', package_name='synthetic', ecosystem='npm', repo='local/litmus',
                       fix_commit_sha='synthetic', file_path='probe.js', function_name=name,
                       vulnerable_function=v, patched_function=p, diagnostic_lines=compute_diagnostic_lines(v, p))


def current_boundary(v, p, c):
    entry = entry_for(v, p)
    pairs = extract_vulnerability_regions(entry)
    candidates = enumerate_candidate_regions(c)
    evidence = [verify_region_pair(x.region, pair, 1.0) for pair in pairs for x in candidates]
    edit = score_edit_distance(c, entry.diagnostic_lines)
    return classify_boundary(evidence, pairs[-1], edit=edit).model_dump(mode='json')


def synthetic_cases():
    # One changed token surrounded by substantial shared code on a single line.
    templates = [
        ('operator', 'if (size <= limit && ready && enabled) { copy(data, size, options); }', 'if (size < limit && ready && enabled) { copy(data, size, options); }'),
        ('string', 'return validate(value, "abc", options, context, mode, source);', 'return validate(value, "abcdefg", options, context, mode, source);'),
        ('regex', 'return sanitize(value, /[^)]/g, options, context, mode, source);', 'return sanitize(value, /[^()]/g, options, context, mode, source);'),
        ('number', 'return validate(value, 256, options, context, mode, source);', 'return validate(value, 255, options, context, mode, source);'),
        ('property', 'return validate(value.abc, options, context, mode, source);', 'return validate(value.abcdefg, options, context, mode, source);'),
        ('call', 'const safe = abc(value, options, context); return validate(safe, mode, source);', 'const safe = abcdefg(value, options, context); return validate(safe, mode, source);'),
    ]
    wrap = lambda body: 'function probe(value, options, context, mode, source) { ' + body + ' }'
    cases = []
    for kind, vbody, pbody in templates:
        v, p = wrap(vbody), wrap(pbody)
        for side, body in [('vulnerable', vbody), ('patched', pbody)]:
            c = wrap('const extra = 0; ' + body.replace('value', 'renamed'))
            cases.append((f'{kind}_{side}', v, p, c, side))
    vbody, pbody = templates[1][1:]
    v, p = wrap(vbody), wrap(pbody)
    cases += [
        ('third_string', v, p, wrap(pbody.replace('abcdefg', 'somethingElse')), 'uncertain'),
        ('same_string_wrong_call', v, p, wrap(pbody.replace('validate', 'unrelated')), 'uncertain'),
        ('both_locations', v, p, wrap(vbody.replace('return ', '') + pbody), 'uncertain'),
        ('neither_location', v, p, wrap('return other(value);'), 'uncertain'),
        ('decoy_literal', v, p, wrap('log("abcdefg"); ' + vbody), 'vulnerable'),
        ('added_guard', wrap('return read(value);'), wrap('if (!allowed(value)) return; return read(value);'), wrap('if (!allowed(value)) return; return read(value);'), 'patched'),
        ('rename_only_reference_diff', wrap('const abc = value; return read(abc);'), wrap('const abcdefg = value; return read(abcdefg);'), wrap('const other = value; return read(other);'), 'uncertain'),
        ('mixed_changes', wrap('return validate(value, "abc", 256, options, context);'), wrap('return validate(value, "abcdefg", 255, options, context);'), wrap('return validate(value, "abcdefg", 256, options, context);'), 'uncertain'),
    ]
    return cases


def run_synthetic():
    rows = []
    for name, v, p, c, expected in synthetic_cases():
        baseline = current_boundary(v, p, c)
        local = localized_delta(v, p, c)
        eligible = baseline['token_gate_passed'] and not baseline['boundary_rejected'] and not baseline['contradictions']
        proposed = baseline['status']
        if proposed == 'uncertain' and eligible and local['status'] != 'uncertain':
            proposed = local['status']
        rows.append(dict(candidate_id=name, vulnerable_source=v, patched_source=p, candidate_source=c,
                         expected=expected, baseline=baseline, localized=local, proposed=proposed))
    return rows


SUITES = [('llm_transformed', 'llm_transformed_positive.jsonl', 'llm_transformed_negative.jsonl', 'llm_transformed_results_contrastive_containment_v3.json'),
          ('deterministic', 'candidate_subset_30.jsonl', 'negative_subset_60.jsonl', 'wider_deterministic_fixture_contrastive_containment_v3.json'),
          ('klaban', 'klaban_verification_positive.jsonl', 'klaban_verification_negative.jsonl', 'wider_klaban_fixture_contrastive_containment_v3.json')]


def run_fixtures():
    rows = []
    for suite, positive, negative, baseline_file in SUITES:
        saved = json.loads((ROOT/'eval'/baseline_file).read_text(encoding='utf-8'))
        by_id = {r['candidate_id']: r for r in saved['results']}
        for filename, expected in [(positive, 'vulnerable'), (negative, 'patched')]:
            for line in (ROOT/'eval'/filename).read_text(encoding='utf-8').splitlines():
                if not line.strip():
                    continue
                r = json.loads(line)
                local = localized_delta(r['vulnerable_function'], r['patched_function'], r['candidate_source'])
                identity = r['corpus_entry']
                entry = CorpusEntry(**{**identity, 'package_name': r.get('package_name','unknown'), 'ecosystem':'npm',
                    'vulnerable_function':r['vulnerable_function'], 'patched_function':r['patched_function'],
                    'source_language': r.get('source_language','javascript')})
                boundary = fix_boundary_id(entry)
                old = by_id.get(r['candidate_id'], {})
                matching = [b for b in old.get('boundary_verification',[]) if b['fix_boundary_id']==boundary]
                eligible = any(b['status']=='uncertain' and b.get('token_gate_passed') and not b.get('boundary_rejected') for b in matching)
                rows.append(dict(candidate_id=r['candidate_id'], suite=suite, clone_type=r.get('clone_type'),
                    expected_side=expected, baseline_outcome=old.get('outcome'), baseline_priority=old.get('priority'),
                    target_boundary=boundary, saved_target_states=matching, eligible_saved_gate=eligible,
                    localized=local, proposed_boundary_resolution=local['status'] if eligible else None,
                    vulnerable_source=r['vulnerable_function'], patched_source=r['patched_function'], candidate_source=r['candidate_source']))
    return rows


def main():
    synthetic = run_synthetic()
    # Mechanism checks, not benchmark-driven thresholds: supported replacements
    # resolve on both sides; negative controls must not invent a side.
    for row in synthetic[:12]:
        assert row['localized']['status'] == row['expected'], row['candidate_id']
    for row in synthetic:
        if row['expected'] == 'uncertain':
            assert row['localized']['status'] == 'uncertain', row['candidate_id']
    fixtures = run_fixtures()
    proposals = [r for r in fixtures if r['proposed_boundary_resolution'] in {'vulnerable','patched'}]
    summary = {
        'synthetic_count': len(synthetic),
        'synthetic_baseline_status': dict(Counter(r['baseline']['status'] for r in synthetic)),
        'synthetic_proposed_status': dict(Counter(r['proposed'] for r in synthetic)),
        'synthetic_changed': [r['candidate_id'] for r in synthetic if r['proposed'] != r['baseline']['status']],
        'synthetic_wrong_decisive_before': [r['candidate_id'] for r in synthetic if r['baseline']['status'] not in {'uncertain',r['expected']}],
        'synthetic_wrong_decisive_after': [r['candidate_id'] for r in synthetic if r['proposed'] not in {'uncertain',r['expected']}],
        'fixture_count': len(fixtures),
        'fixture_saved_target_boundary_found': sum(bool(r['saved_target_states']) for r in fixtures),
        'fixture_eligible_uncertain_target_boundaries': sum(r['eligible_saved_gate'] for r in fixtures),
        'fixture_localized_status': dict(Counter(r['localized']['status'] for r in fixtures)),
        'eligible_boundary_proposals': len(proposals),
        'proposal_matches_expected_side': sum(r['proposed_boundary_resolution']==r['expected_side'] for r in proposals),
        'proposal_disagrees_expected_side': sum(r['proposed_boundary_resolution']!=r['expected_side'] for r in proposals),
        'localized_decisive_disagrees_expected_side': sum(r['localized']['status'] not in {'uncertain',r['expected_side']} for r in fixtures),
        'proposals': [{k:r[k] for k in ['candidate_id','suite','expected_side','baseline_outcome','proposed_boundary_resolution']} for r in proposals],
        'unresolved_change_reasons': dict(Counter(d.get('reason','resolved') for r in fixtures for d in r['localized']['changes'])),
    }
    payload = dict(schema='localized_delta_litmus_v1', generated_at_utc=datetime.now(timezone.utc).isoformat(),
        methodology='Isolated token-flank localization, exact replacement comparison; unchanged production S/T/E thresholds. Synthetic current boundary verifier uses all enumerated region comparisons, no retrieval or hash bypass. Fixture pass only examines known target references and reuses saved target-boundary S/T gates; no full pipeline rerun or aggregate FP/abstention claims. All edits must resolve consistently. Added/deleted code is unsupported in v1.',
        configuration={'flank_tokens':16,'minimum_flank_tokens':3,'candidate_gap':'reference replacement lengths only','baseline_E_side':.9,'baseline_E_margin':.1},
        summary=summary, results=synthetic+fixtures)
    out=ROOT/'eval'/'localized_delta_litmus.json'
    out.write_text(json.dumps(payload, indent=2), encoding='utf-8')
    print(json.dumps(summary, indent=2))


if __name__=='__main__':
    main()
