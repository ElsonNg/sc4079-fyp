"""Refresh the offline pipeline guide's examples and saved-evaluation inventory.

Run from the repository root: .venv/Scripts/python.exe scripts/build_pipeline_guide_data.py
This reads existing evaluations; it does not rerun the benchmarks.
"""
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from pipeline.controller.hashing import abstract_identifiers, compute_fingerprint
from pipeline.controller.parsing import normalize_source, _collapse_whitespace
from pipeline.controller.region_extraction import enumerate_candidate_regions
from pipeline.detection.verification.structural import structural_score as _structural_score
from pipeline.detection.verification.tokens import token_score as _token_score, role_tokens as _role_tokens
from pipeline.detection.verification.sequences import sequence_similarity as _ratio
from pipeline.detection.verification.edit_distance import role_tokens, fuzzy_substring_similarity


def example_data():
    sources = {
        'Reference': 'function readValue(record, key) {\n  const value = record[key];\n  return value;\n}',
        'Type I: comments / whitespace': 'function readValue(record, key) {\n    // Read the requested property.\n    const value = record[key];\n    return value;\n}',
        'Type II: renamed parameters / local': 'function readValue(object, name) {\n  const result = object[name];\n  return result;\n}',
        'Type III: added statement': 'function readValue(record, key) {\n  const unused = 0;\n  const value = record[key];\n  return value;\n}',
        'Patch: reject one dangerous key': 'function readValue(record, key) {\n  if (key === "__proto__") return undefined;\n  const value = record[key];\n  return value;\n}',
    }
    regions = {name: next(x.region for x in enumerate_candidate_regions(source) if x.region.granularity == 'function') for name, source in sources.items()}
    ref = regions['Reference']
    out = []
    for name, source in sources.items():
        r = regions[name]
        out.append(dict(name=name, source=source, normalized=' '.join(normalize_source(source)),
                        abstracted=' '.join(_collapse_whitespace(abstract_identifiers(source))),
                        native_hash=hashlib.sha256(source.encode()).hexdigest(),
                        fingerprint=compute_fingerprint(source).model_dump(),
                        shape=r.ast_shape, path=r.ast_path, tokens=_role_tokens(r),
                        e_tokens=role_tokens(source), shape_score=_ratio(r.ast_shape, ref.ast_shape),
                        path_score=_ratio(r.ast_path, ref.ast_path), S=_structural_score(r, ref), T=_token_score(r, ref)))
    removed = 'return input.replace(/[^)]/g, "");'
    added = 'return input.replace(/[^()]/g, "");'
    cases = [('Transformed vulnerable', 'function clean(text) { const unused = 0; return text.replace(/[^)]/g, ""); }'),
             ('Transformed patched', 'function clean(text) { const unused = 0; return text.replace(/[^()]/g, ""); }')]
    edits = []
    for name, source in cases:
        ev = fuzzy_substring_similarity(role_tokens(removed), role_tokens(source))
        ep = fuzzy_substring_similarity(role_tokens(added), role_tokens(source))
        edits.append(dict(name=name, source=source, tokens=role_tokens(source), Ev=ev, Ep=ep, margin=ev-ep))
    return dict(fingerprints=out, removed=removed, added=added, removed_tokens=role_tokens(removed), added_tokens=role_tokens(added), edits=edits)


def main():
    artifacts = []
    for path in sorted((ROOT / 'eval').glob('*.json')):
        if '.checkpoint.' in path.name:
            artifacts.append(dict(file=path.name, checkpoint=True, bytes=path.stat().st_size,
                                  metadata={'note': 'Resume state, not an independent completed test. Linked only; not loaded into this page.'}, rows=[]))
            continue
        data = json.loads(path.read_text(encoding='utf-8'))
        metadata = {k: v for k, v in data.items() if k not in {'results', 'background_noise'}}
        if 'background_noise' in data:
            metadata['background_noise_note'] = 'Full background findings are in the linked source artifact; aggregate counts remain in summary.'
        results = data.get('results', [])
        rows = []
        if isinstance(results, list):
            for row in results:
                if not isinstance(row, dict):
                    continue
                keys = ['candidate_id', 'sample_id', 'id', 'expected_status', 'clone_type', 'source_language', 'package_name', 'priority', 'outcome', 'retrieval_rank', 'hash_match_types', 'boundary_verification', 'corpus_entry']
                compact = {k: row[k] for k in keys if k in row}
                if data.get('schema') in {'localized_delta_litmus_v1', 'localized_abstention_investigation_v1', 'expression_regex_litmus_v1', 'guard_order_inspection_v1', 'guard_order_static_litmus_v1', 'guard_order_ablation_v1', 'disjoint_guard_order_screen_v1'}:
                    compact = row
                if data.get('schema') == 'conservative_review_ablation_v1':
                    compact = {k:v for k,v in row.items() if k != 'original_detection'}
                if compact:
                    rows.append(compact)
        artifacts.append(dict(file=path.name, metadata=metadata, rows=rows, result_count=len(results), bytes=path.stat().st_size))
    payload = dict(generated=datetime.now(timezone.utc).isoformat(), examples=example_data(), artifacts=artifacts)
    target = ROOT / 'docs' / 'verification-pipeline-data.js'
    target.write_text('window.PIPELINE_GUIDE_DATA = ' + json.dumps(payload, ensure_ascii=True, separators=(',', ':')) + ';\n', encoding='utf-8')
    print(f'Wrote {len(artifacts)} artifact entries and computed examples to {target.name} ({target.stat().st_size:,} bytes)')


if __name__ == '__main__':
    main()
