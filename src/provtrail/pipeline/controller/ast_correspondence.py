"""Whole-function AST correspondence with lexical binding identity.

This checks copied structure, not arbitrary semantic equivalence. Operations,
control flow, free names, property keys, literals and binding relationships remain
visible. Unsupported or reflective code abstains. No candidate code is executed.
"""
from dataclasses import dataclass, field

from provtrail.pipeline.controller.region_extraction import _parse_region_source, _function_root
from provtrail.pipeline.controller.local_correspondence import Unsupported, walk, text


FUNCTIONS = {"function_declaration", "function_expression", "arrow_function",
             "method_definition", "generator_function", "generator_function_declaration"}
SCOPES = {"statement_block", "for_statement", "for_in_statement", "catch_clause", "switch_body"}
FORBIDDEN = {"with_statement", "class", "class_declaration", "class_body", "decorator",
             "namespace_export", "internal_module"}


@dataclass
class Scope:
    parent: "Scope | None"
    index: int
    function: bool = False
    bindings: dict = field(default_factory=dict)

    def declare(self, node, token, *, redeclare=False):
        if node is None or node.type not in {"identifier", "shorthand_property_identifier_pattern"}:
            raise Unsupported("complex_binding")
        name = text(node)
        if name == "undefined":
            raise Unsupported("shadowed_undefined")
        if name in self.bindings and not redeclare:
            raise Unsupported("duplicate_binding")
        self.bindings.setdefault(name, token)

    def resolve(self, name):
        if name in self.bindings:
            return self.bindings[name]
        return self.parent.resolve(name) if self.parent else ("external", name)


def ast_form(source, filename="candidate.js", *, remove_noop=False):
    """Preserve complete syntax modulo comments, grouping and bound-name renames."""
    if len(source) > 40000:
        raise Unsupported("source_size_limit")
    parsed = _parse_region_source(source, filename)
    if parsed.tree.root_node.has_error:
        raise Unsupported("parse_error")
    root = _function_root(parsed)
    if root.type not in FUNCTIONS:
        raise Unsupported("function_required")
    raw = source.encode("utf-8")
    start, end = root.start_byte-parsed.byte_offset, root.end_byte-parsed.byte_offset
    if start < 0 or end > len(raw):
        raise Unsupported("outer_wrapper")
    if raw[:start].strip(b" \r\n\t(") or raw[end:].strip(b" \r\n\t);"):
        raise Unsupported("surrounding_code")
    nodes = list(walk(root))
    if len(nodes) > 6000:
        raise Unsupported("node_limit")
    for node in nodes:
        if node.type in FORBIDDEN:
            raise Unsupported(node.type)
        if node.type == "identifier" and text(node) in {"eval", "arguments", "Function"}:
            raise Unsupported("dynamic_scope_or_reflection")
    scopes, binding_nodes = {}, {}
    count = 0
    binding_count = 0
    declaration_kinds = {}

    def new_scope(parent, function=False):
        nonlocal count
        result = Scope(parent, count, function)
        count += 1
        return result

    def declare(node, scope, *, kind="lexical"):
        nonlocal binding_count
        if node is None:
            raise Unsupported("missing_binding")
        existed = text(node) in scope.bindings
        redeclare = kind == "var" and declaration_kinds.get((scope.index, text(node))) in {"var", "parameter"}
        scope.declare(node, ("binding", binding_count), redeclare=redeclare)
        if not existed:
            binding_count += 1
        binding_nodes[node.id] = scope.resolve(text(node))
        declaration_kinds.setdefault((scope.index, text(node)), kind)

    def pattern(node, scope, *, kind="lexical"):
        if node is None:
            raise Unsupported("missing_pattern")
        if node.type in {"identifier", "shorthand_property_identifier_pattern"}:
            declare(node, scope, kind=kind)
        elif node.type in {"object_pattern", "array_pattern", "rest_pattern"}:
            for child in node.named_children:
                if child.type != "comment":
                    pattern(child, scope, kind=kind)
        elif node.type in {"assignment_pattern", "object_assignment_pattern"}:
            pattern(node.child_by_field_name("left"), scope, kind=kind)
        elif node.type == "pair_pattern":
            pattern(node.child_by_field_name("value"), scope, kind=kind)
        else:
            raise Unsupported("complex_binding_" + node.type)

    def parameter(node, scope):
        if node.type in {"required_parameter", "optional_parameter"}:
            node = node.child_by_field_name("pattern")
        if node is not None and node.type == "assignment_pattern":
            node = node.child_by_field_name("left")
        if node is not None and node.type == "rest_pattern":
            named = node.named_children
            node = named[0] if len(named) == 1 else None
        pattern(node, scope, kind="parameter")

    def assign(node, scope):
        if node.type in FUNCTIONS:
            name = node.child_by_field_name("name")
            outer_name = node != root and node.type in {"function_declaration", "generator_function_declaration"}
            if outer_name:
                if node.parent.type != "statement_block" or node.parent.parent.type not in FUNCTIONS:
                    raise Unsupported("block_function_declaration")
                declare(name, scope)
            scope = new_scope(scope, function=True)
            if name is not None and name.type == "identifier" and not outer_name:
                declare(name, scope)
            params = node.child_by_field_name("parameters") or node.child_by_field_name("parameter")
            if params is None:
                raise Unsupported("parameters")
            for p in params.named_children if params.type == "formal_parameters" else [params]:
                if p.type != "comment":
                    parameter(p, scope)
        elif node.type in SCOPES:
            scope = new_scope(scope)
            if node.type == "catch_clause":
                arg = node.child_by_field_name("parameter")
                if arg is not None:
                    pattern(arg, scope)
        scopes[node.id] = scope
        if node.type == "variable_declarator":
            target = scope
            if node.parent.type == "variable_declaration":
                while target and not target.function:
                    target = target.parent
            if target is None:
                raise Unsupported("unscoped_var")
            pattern(node.child_by_field_name("name"), target,
                    kind="var" if node.parent.type == "variable_declaration" else "lexical")
        if node.type == "for_in_statement":
            kind = node.child_by_field_name("kind")
            if kind is not None:
                target = scope
                if text(kind) == "var":
                    while target and not target.function:
                        target = target.parent
                pattern(node.child_by_field_name("left"), target, kind="var" if text(kind)=="var" else "lexical")
        for child in node.named_children:
            assign(child, scope)

    assign(root, None)

    # Reflection on locally created functions can observe renamed source/names.
    sensitive = {binding_nodes[n.child_by_field_name("name").id] for n in nodes
                 if n.type in FUNCTIONS and n.child_by_field_name("name") is not None
                 and n.child_by_field_name("name").id in binding_nodes}
    for n in nodes:
        if n.type == "variable_declarator":
            value = n.child_by_field_name("value")
            name = n.child_by_field_name("name")
            if value is not None and any(c.type in FUNCTIONS for c in walk(value)) and name.id in binding_nodes:
                sensitive.add(binding_nodes[name.id])
    # Include simple aliases; use a conservative rejection for compound aliases.
    for _ in range(len(nodes)):
        prior = len(sensitive)
        for n in nodes:
            if n.type == "variable_declarator":
                value, name = n.child_by_field_name("value"), n.child_by_field_name("name")
                if value is not None and name.id in binding_nodes and any(
                    c.type == "identifier" and scopes[c.id].resolve(text(c)) in sensitive for c in walk(value)):
                    sensitive.add(binding_nodes[name.id])
            elif n.type == "assignment_expression":
                value, name = n.child_by_field_name("right"), n.child_by_field_name("left")
                if name is not None and name.type == "identifier" and value is not None and any(
                    c.type in FUNCTIONS or (c.type == "identifier" and scopes[c.id].resolve(text(c)) in sensitive) for c in walk(value)):
                    sensitive.add(scopes[name.id].resolve(text(name)))
        if prior == len(sensitive):
            break
    for n in nodes:
        if n.type in {"member_expression", "subscript_expression"}:
            prop = n.child_by_field_name("property") or n.child_by_field_name("index")
            property_name = text(prop)
            if prop is not None and prop.type == "string" and "\\" not in property_name:
                property_name = property_name[1:-1]
            obj = n.child_by_field_name("object")
            if property_name in {"name", "toString", "caller", "callee"} and any(
                c.type == "identifier" and scopes[c.id].resolve(text(c)) in sensitive for c in walk(obj)):
                raise Unsupported("possible_name_or_source_reflection")
            method_name = root.child_by_field_name("name")
            if root.type == "method_definition" and obj.type == "this" and (
                property_name == text(method_name) or n.type == "subscript_expression"):
                raise Unsupported("method_self_reference")

    written = set()
    for n in nodes:
        if n.type in {"assignment_expression", "augmented_assignment_expression", "update_expression"}:
            left = n.child_by_field_name("left") or n.child_by_field_name("argument")
            if left is not None and left.type not in {"member_expression", "subscript_expression"}:
                written.update(scopes[c.id].resolve(text(c)) for c in walk(left)
                               if c.type in {"identifier", "shorthand_property_identifier_pattern"})

    def is_noop(node):
        # A statically false branch cannot evaluate its body. Keep declarations
        # and all other bodies: even an unreachable var can change binding scope.
        if node.type != "if_statement" or node.child_by_field_name("alternative") is not None:
            return False
        condition = node.child_by_field_name("condition")
        while condition is not None and condition.type == "parenthesized_expression":
            condition = condition.named_children[0]
        body = node.child_by_field_name("consequence")
        return (condition is not None and condition.type == "false" and body is not None
                and "".join(text(body).split()) in {"{void0;}", "void0;", "{void0}"})

    def canon(node):
        if node.type == "comment" or (remove_noop and is_noop(node)):
            return None
        if node.type == "identifier":
            return binding_nodes.get(node.id, scopes[node.id].resolve(text(node)))
        if node.type in {"type_annotation", "type_parameters", "type_arguments", "accessibility_modifier"}:
            return None
        if node.type in {"required_parameter", "optional_parameter"}:
            p = node.child_by_field_name("pattern")
            value = node.child_by_field_name("value")
            return ("assignment_pattern", (("left", canon(p)), ("right", canon(value)))) if value else canon(p)
        if node.type in {"shorthand_property_identifier", "shorthand_property_identifier_pattern"}:
            kind = "pair_pattern" if node.type.endswith("pattern") else "pair"
            return (kind, (("key", ("property_identifier", text(node))),
                           ("value", binding_nodes.get(node.id, scopes[node.id].resolve(text(node))))))
        if node.type in {"pair", "pair_pattern"}:
            key = node.child_by_field_name("key")
            proto = node.type == "pair" and (text(key) == "__proto__" or
                    key.type == "string" and text(key)[1:-1] == "__proto__")
            return ("prototype_setter" if proto else node.type, (("key", canon(key)),
                                ("value", canon(node.child_by_field_name("value")))))
        if node.type == "string" and "\\" not in text(node):
            return ("string_value", text(node)[1:-1])
        if node.type == "statement_block":
            return sequence(node.named_children)
        if node.type == "if_statement":
            cons = node.child_by_field_name("consequence")
            alt = node.child_by_field_name("alternative")
            if alt is not None and alt.type == "else_clause":
                alt = next(n for n in alt.named_children if n.type != "comment")
            return ("if", canon(node.child_by_field_name("condition")),
                    sequence(cons.named_children if cons.type == "statement_block" else [cons]),
                    sequence(alt.named_children if alt is not None and alt.type == "statement_block" else [alt] if alt else []))
        if node == root.child_by_field_name("name") and root.type == "method_definition":
            # Only the public method label is renameable, not computed/private keys.
            if node.type != "property_identifier":
                raise Unsupported("computed_or_private_method")
            return ("method_name", text(node) if text(node) == "constructor" else "public")
        if node.type == "parenthesized_expression":
            # Grouping around optional chaining and directive strings is meaningful.
            directive = node.parent.type == "expression_statement" and any(n.type == "string" for n in walk(node))
            if not directive and not any(n.type == "optional_chain" for n in walk(node)):
                return canon(node.named_children[0])
        if not node.children:
            return (node.type, text(node))
        parts = []
        for i, child in enumerate(node.children):
            if not child.is_named and child.type == ";":
                continue
            value = canon(child)
            if node.type == "lexical_declaration" and child.type in {"const", "let"}:
                names = [b for d in node.named_children if d.type == "variable_declarator"
                         for b in walk(d.child_by_field_name("name")) if b.id in binding_nodes]
                if names and not any(binding_nodes[b.id] in written for b in names):
                    value = ("immutable_lexical",)
            if value is not None:
                parts.append((node.field_name_for_child(i), value))
        return (node.type, tuple(parts))

    def sequence(items):
        items = [n for n in items if n.type != "comment" and not (remove_noop and is_noop(n))]
        if not items:
            return ("end",)
        head, *tail = items
        if head.type == "lexical_declaration" and len(head.named_children) == 1 and len(tail) == 1 and tail[0].type == "return_statement":
            decl = head.named_children[0]
            name, value = decl.child_by_field_name("name"), decl.child_by_field_name("value")
            returned = tail[0].named_children
            if (name is not None and name.type == "identifier" and value is not None
                and len(returned) == 1 and returned[0].type == "identifier"
                and scopes[returned[0].id].resolve(text(returned[0])) == binding_nodes[name.id]
                and not any(n.type in FUNCTIONS for n in walk(value))):
                return ("sequence", ("return_statement", ((None, ("return", "return")), (None, canon(value)))), ("end",))
        if head.type == "if_statement":
            cons = head.child_by_field_name("consequence")
            branch = list(cons.named_children) if cons.type == "statement_block" else [cons]
            branch = [n for n in branch if n.type != "comment"]
            if branch and branch[-1].type in {"return_statement", "throw_statement"} and not any(
                n.type in FUNCTIONS for n in walk(cons)):
                alt = head.child_by_field_name("alternative")
                if alt is not None and alt.type == "else_clause":
                    alt = next(n for n in alt.named_children if n.type != "comment")
                if alt is not None and any(n.type in FUNCTIONS for n in walk(alt)):
                    return ("sequence", canon(head), sequence(tail))
                other = list(alt.named_children) if alt is not None and alt.type == "statement_block" else [alt] if alt else []
                return ("terminal_if", canon(head.child_by_field_name("condition")), sequence(branch), sequence(other+tail))
        return ("sequence", canon(head), sequence(tail))

    # Removed no-op scopes/temporary bindings must not shift the identities of
    # remaining bindings. Preserve equality relationships, rename tokens by their
    # first occurrence in the resulting complete form.
    bindings = {}
    def renumber(value):
        if isinstance(value, tuple) and len(value) == 2 and value[0] == "binding" and isinstance(value[1], int):
            return ("binding", bindings.setdefault(value[1], len(bindings)))
        if isinstance(value, tuple):
            return tuple(renumber(v) for v in value)
        return value
    return renumber(canon(root))


def compare_ast(vulnerable, patched, candidate, filename="candidate.js", *, remove_noop=False):
    forms, failures = {}, {}
    for side, source in (("vulnerable", vulnerable), ("patched", patched), ("candidate", candidate)):
        try:
            forms[side] = ast_form(source, filename, remove_noop=remove_noop)
        except (Unsupported, RecursionError) as exc:
            failures[side] = str(exc) or "depth_limit"
    if failures:
        return dict(status="uncertain", reason="unsupported_ast", failures=failures)
    if forms["vulnerable"] == forms["patched"]:
        return dict(status="uncertain", reason="no_reference_distinction")
    matched = [side for side in ("vulnerable", "patched") if forms["candidate"] == forms[side]]
    return dict(status=matched[0] if matched else "uncertain",
                reason="whole_function_binding_correspondence" if matched else "matches_neither_reference",
                normalization="comments_grouping_bindings" + ("_dead_void_branch" if remove_noop else ""))
