"""Conservative full-tree source preservation for additional Tier 2 variants.

No execution or security-input construction. This proves only syntax-preserving
local-binding renames and leaves structural edits for explicit review.
"""
from __future__ import annotations

from collections import Counter

from eval.tier2.source_review import FORBIDDEN, leaves, parsed, signature


def binding_sequence(root):
    found = []
    def pattern(node):
        if node is None:
            return
        if node.type == 'identifier':
            found.append(node.text.decode())
        elif node.type == 'shorthand_property_identifier_pattern':
            found.append(node.text.decode())
        elif node.type in {'required_parameter', 'optional_parameter'}:
            pattern(node.child_by_field_name('pattern'))
        elif node.type in {'assignment_pattern', 'object_assignment_pattern'}:
            pattern(node.child_by_field_name('left'))
        elif node.type == 'pair_pattern':
            pattern(node.child_by_field_name('value'))
        elif node.type in {'rest_pattern', 'spread_element'}:
            for child in node.named_children:
                pattern(child)
        elif node.type in {'object_pattern', 'array_pattern'}:
            for child in node.named_children:
                pattern(child)
    def walk(node):
        if node.type == 'variable_declarator':
            pattern(node.child_by_field_name('name'))
        elif node.type == 'catch_clause':
            pattern(node.child_by_field_name('parameter'))
        elif node.type == 'formal_parameters':
            for child in node.named_children:
                pattern(child)
        elif node.type == 'arrow_function':
            pattern(node.child_by_field_name('parameter'))
        for child in node.children:
            walk(child)
    walk(root)
    return found


def bindings(root):
    return Counter(binding_sequence(root))


def canonical(root, renames=None):
    """Expand JS/TS shorthand properties, preserving their external keys."""
    renames = renames or {}
    if root.type in {'comment', ';'}:
        return None
    if root.type == 'parenthesized_expression':
        named = [child for child in root.named_children if child.type != 'comment']
        if len(named) == 1:
            return canonical(named[0], renames)
    if root.type in {'shorthand_property_identifier_pattern', 'shorthand_property_identifier'}:
        name = root.text.decode()
        kind = 'pair_pattern' if root.type.endswith('_pattern') else 'pair'
        return (kind, (('property_identifier', name), ('colon', ':'),
                       ('identifier', renames.get(name, name))))
    if root.type in {'pair_pattern', 'pair'}:
        key = root.child_by_field_name('key')
        value = root.child_by_field_name('value')
        if key is not None and value is not None:
            return (root.type, (canonical(key, renames), ('colon', ':'),
                                canonical(value, renames)))
    children = [value for child in root.children
                if (value := canonical(child, renames)) is not None]
    if children:
        return (root.type, tuple(children))
    value = root.text.decode()
    return (root.type, renames.get(value, value) if root.type == 'identifier' else value)


def compare_shorthand_aliases(source, candidate, language):
    """Prove full-tree equality across consistent shorthand-local renames."""
    try:
        a, b = parsed(source, language), parsed(candidate, language)
    except ValueError as exc:
        return {'preserved': False, 'reason': str(exc)}
    seq_a, seq_b = binding_sequence(a), binding_sequence(b)
    if len(seq_a) != len(seq_b):
        return {'preserved': False, 'reason': 'binding_count_changed'}
    pairs = list(zip(seq_a, seq_b))
    mapping = dict(pairs)
    if any(mapping[x] != y for x, y in pairs) or len(set(mapping.values())) != len(mapping):
        return {'preserved': False, 'reason': 'inconsistent_or_nonbijective_binding_rename'}
    changed = {x: y for x, y in mapping.items() if x != y}
    counts_a, counts_b = Counter(seq_a), Counter(seq_b)
    if any(counts_a[x] != 1 or counts_b[y] != 1 for x, y in changed.items()):
        return {'preserved': False, 'reason': 'shadowed_binding_requires_review'}
    if any(n.type == 'with_statement' or n.text.decode() in {'eval', 'Function', 'caller', 'callee'}
           for root in (a, b) for n in leaves(root)):
        return {'preserved': False, 'reason': 'reflection_requires_review'}
    def inferred_function_name(root):
        found = set()
        def walk(node):
            if node.type == 'variable_declarator':
                name = node.child_by_field_name('name')
                value = node.child_by_field_name('value')
                if name is not None and name.type == 'identifier' and value is not None and value.type in {
                    'arrow_function', 'function_expression', 'class'}:
                    found.add(name.text.decode())
            for child in node.children:
                walk(child)
        walk(root)
        return found
    if set(changed) & inferred_function_name(a):
        return {'preserved': False, 'reason': 'inferred_function_name_changes'}
    free_a = {n.text.decode() for n in leaves(a) if n.type == 'identifier'} - set(seq_a)
    if set(changed.values()) & free_a:
        return {'preserved': False, 'reason': 'capture_risk'}
    if canonical(a, changed) != canonical(b):
        return {'preserved': False, 'reason': 'other_structural_change'}
    return {'preserved': True, 'reason': 'full_tree_shorthand_binding_rename', 'renames': changed}


def compare(source, candidate, language):
    try:
        a, b = parsed(source, language), parsed(candidate, language)
    except ValueError as exc:
        return {'preserved': False, 'reason': str(exc)}
    if source == candidate:
        return {'preserved': True, 'reason': 'byte_identical'}
    def shape(node):
        if node.type == 'comment':
            return None
        children = [s for child in node.children if (s := shape(child)) is not None]
        return (node.type, tuple(children)) if children else (node.type, '_') if node.type == 'identifier' else (node.type, node.text.decode())
    if shape(a) != shape(b):
        return {'preserved': False, 'reason': 'structural_change'}
    la = [n for n in leaves(a) if n.type != 'comment']
    lb = [n for n in leaves(b) if n.type != 'comment']
    changes = [(x.text.decode(), y.text.decode()) for x, y in zip(la, lb)
               if x.type == 'identifier' and x.text != y.text]
    if not changes:
        return {'preserved': True, 'reason': 'identical_syntax_tree'}
    if any(n.text.decode() in FORBIDDEN or n.type in FORBIDDEN for root in (a, b) for n in leaves(root)):
        return {'preserved': False, 'reason': 'reflection_requires_review'}
    declared_a, declared_b = bindings(a), bindings(b)
    if any(x not in declared_a or y not in declared_b for x, y in changes):
        return {'preserved': False, 'reason': 'changed_nonlocal_identifier'}
    mapping = {}
    for x, y in changes:
        if x in mapping and mapping[x] != y:
            return {'preserved': False, 'reason': 'inconsistent_rename'}
        mapping[x] = y
    if len(set(mapping.values())) != len(mapping):
        return {'preserved': False, 'reason': 'non_bijective_rename'}
    if any(declared_a[x] != 1 or declared_b[y] != 1 for x, y in mapping.items()):
        return {'preserved': False, 'reason': 'shadowed_binding_requires_review'}
    if any(n.type in {'shorthand_property_identifier', 'shorthand_property_identifier_pattern'}
           and n.text.decode() in mapping for root in (a, b) for n in leaves(root)):
        return {'preserved': False, 'reason': 'shorthand_property_requires_review'}
    free_a = {n.text.decode() for n in la if n.type == 'identifier'} - set(declared_a)
    if set(mapping.values()) & free_a:
        return {'preserved': False, 'reason': 'capture_risk'}
    if signature(a, mapping) != signature(b):
        return {'preserved': False, 'reason': 'incomplete_rename'}
    return {'preserved': True, 'reason': 'full_tree_local_binding_rename', 'renames': mapping}
