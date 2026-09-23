"""Probe safe, paired local-binding renames for Tier 2 expansion."""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
from pathlib import Path

from eval.ablation.common import entry_identity, source_key
from eval.common import DEFAULT_SNAPSHOT_DB
from eval.tier2.extend_validation_v3 import build_records, read_jsonl
from eval.tier2.generate_llm_transformed_subset import _base_record
from eval.tier2.cohort import screen
from eval.tier2.source_review import leaves, parsed
from eval.tier2.static_preservation import compare_shorthand_aliases
from provtrail.corpus.integrations.sqlite_store import load_entries

ROOT = Path(__file__).resolve().parents[2]


def top_function(root):
    functions = []
    def walk(node):
        if node.type in {'function_declaration', 'function_expression', 'arrow_function',
                         'method_definition', 'generator_function', 'generator_function_declaration'}:
            functions.append(node)
        for child in node.children:
            walk(child)
    walk(root)
    return max(functions, key=lambda n: n.end_byte - n.start_byte, default=None)


def names(source, language):
    root = parsed(source, language)
    function = top_function(root)
    if function is None:
        return []
    body = function.child_by_field_name('body')
    if body is None:
        return []
    candidates = []
    parameters = function.child_by_field_name('parameters') or function.child_by_field_name('parameter')
    if parameters is not None:
        if parameters.type == 'identifier':
            candidates.append(parameters.text.decode())
        else:
            for child in parameters.named_children:
                name = child.child_by_field_name('pattern') if child.type in {'required_parameter', 'optional_parameter'} else child
                if name is not None and name.type == 'identifier':
                    candidates.append(name.text.decode())
    for child in body.named_children:
        if child.type in {'lexical_declaration', 'variable_declaration'}:
            for declaration in child.named_children:
                if declaration.type == 'variable_declarator':
                    name = declaration.child_by_field_name('name')
                    if name is not None and name.type == 'identifier':
                        candidates.append(name.text.decode())
    forbidden_nodes = {'shorthand_property_identifier', 'shorthand_property_identifier_pattern'}
    leaves_all = leaves(root)
    count = Counter(n.text.decode() for n in leaves_all if n.type == 'identifier')
    prohibited = {n.text.decode() for n in leaves_all if n.type in forbidden_nodes}
    def safe_occurrences(name):
        for node in leaves_all:
            if node.type != 'identifier' or node.text.decode() != name:
                continue
            if not (function.start_byte <= node.start_byte < function.end_byte):
                return False
            ancestor = node.parent
            while ancestor is not None:
                if ancestor.type in {'type_annotation', 'type_arguments', 'type_parameters',
                                     'type_predicate', 'type_query'}:
                    return False
                ancestor = ancestor.parent
        return True
    return [name for name in dict.fromkeys(candidates)
            if name not in prohibited and count[name] >= 2 and safe_occurrences(name)]


def renamed(source, language, old, new):
    root = parsed(source, language)
    nodes = [n for n in leaves(root) if n.type == 'identifier' and n.text.decode() == old]
    encoded = source.encode('utf8')
    for node in sorted(nodes, key=lambda n: n.start_byte, reverse=True):
        encoded = encoded[:node.start_byte] + new.encode('utf8') + encoded[node.end_byte:]
    return encoded.decode('utf8')


def candidates():
    entries = load_entries(DEFAULT_SNAPSHOT_DB)
    origin_counts = Counter(entry_identity(entry) for entry in entries)
    t1 = read_jsonl(ROOT / 'eval/frozen/tier1-advisory-audit-v1/cases.jsonl')
    valid = defaultdict(set)
    for row in t1:
        if row['verdict'] == 'valid_advisory_reference':
            valid[tuple(row['origin'])].add(row['reference_side'])
    existing = [r for r in build_records(entries) if r['tier'] == 'tier2']
    seen = {source_key(r['candidate_source'], r['source_language']) for r in existing}
    results = []
    for entry in entries:
        origin = entry_identity(entry)
        if valid[origin] != {'vulnerable', 'patched'} or origin_counts[origin] != 1:
            continue
        if max(len(entry.vulnerable_function), len(entry.patched_function)) > 20000:
            continue
        language = entry.origin.source_language
        overlap = sorted(set(names(entry.vulnerable_function, language)) & set(names(entry.patched_function, language)))
        for old in overlap:
            new = 'auditLocal' + hashlib.sha256((str(origin) + old).encode()).hexdigest()[:10]
            transformed = [renamed(source, language, old, new) for source in
                           (entry.vulnerable_function, entry.patched_function)]
            reviews = [compare_shorthand_aliases(source, candidate, language) for source, candidate in zip(
                (entry.vulnerable_function, entry.patched_function), transformed)]
            keys = [source_key(candidate, language) for candidate in transformed]
            screens = []
            for side, candidate in zip(('flagged', 'cleared'), transformed):
                record = _base_record(entry, candidate, 'type_2')
                record['expected_status'] = side
                reasons, gate = screen(record, entry)
                screens.append(not reasons and gate['passed'])
            if all(r['preserved'] for r in reviews) and all(screens) and keys[0] != keys[1] and all(key not in seen for key in keys):
                results.append((entry, old, new, transformed, reviews, keys))
                seen.update(keys)
                break
    return results


if __name__ == '__main__':
    found = candidates()
    print('pair opportunities', len(found), 'cases', 2 * len(found))
    print('packages', Counter(entry.advisory.package_name for entry, *_ in found))
