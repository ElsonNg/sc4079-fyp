"""Conservative automated source/patch review for mechanically checkable rewrites.

This is a deliberately incomplete reviewer. It accepts unchanged syntax trees
(ignoring comments/formatting) and capture-free, consistent renames of uniquely
declared simple local bindings. It does not infer preservation from anchors or
similarity. Structural rewrites, shadowing, shorthand properties and reflective
code need a separate executable test or documented review.
"""
from __future__ import annotations

import difflib
from eval.ablation.common import digest
from provtrail.pipeline.controller.parsing import parse_source

REVIEWER = {"name": "conservative-ast-source-patch-review", "version": "1", "type": "automated"}
FORBIDDEN = {"eval", "Function", "toString", "caller", "callee", "with_statement", "name"}


def parsed(source, language):
    for text in (source, "class __Wrapper {\n" + source + "\n}"):
        tree = parse_source(text, language=language)
        if not tree.root_node.has_error:
            return tree.root_node
    raise ValueError("source_parse_error")


def leaves(root):
    if root.type == "comment":
        return []
    if not root.children:
        return [root]
    return [n for child in root.children for n in leaves(child)]


def signature(root, renames=None):
    renames = renames or {}
    if root.type == "comment":
        return None
    children = [s for c in root.children if (s := signature(c, renames)) is not None]
    if children:
        return (root.type, tuple(children))
    text = root.text.decode()
    return (root.type, renames.get(text, text) if root.type == "identifier" else text)


def binding_nodes(root):
    bindings = []
    def walk(n):
        if n.type in {"variable_declarator", "catch_clause"}:
            field = "name" if n.type == "variable_declarator" else "parameter"
            name = n.child_by_field_name(field)
            if name is not None:
                if name.type != "identifier":
                    raise ValueError("destructured_binding_requires_review")
                bindings.append(name)
        elif n.type == "formal_parameters":
            for child in n.named_children:
                if child.type == "comment":
                    continue
                name = child
                if child.type in {"required_parameter", "optional_parameter"}:
                    name = child.child_by_field_name("pattern")
                if name is None or name.type != "identifier":
                    raise ValueError("complex_parameter_requires_review")
                bindings.append(name)
        elif n.type == "arrow_function":
            parameter = n.child_by_field_name("parameter")
            if parameter is not None:
                if parameter.type != "identifier":
                    raise ValueError("complex_arrow_parameter_requires_review")
                bindings.append(parameter)
        for child in n.children:
            walk(child)
    walk(root)
    names = [n.text.decode() for n in bindings]
    if len(set(names)) != len(names):
        raise ValueError("shadowed_or_redeclared_bindings_require_review")
    return names


def equivalence(source, candidate, language):
    try:
        a, b = parsed(source, language), parsed(candidate, language)
        for root in (a, b):
            if any(n.text.decode() in FORBIDDEN or n.type in FORBIDDEN for n in leaves(root)):
                raise ValueError("reflection_requires_review")
        if signature(a) == signature(b):
            return {"preserved": True, "classification": "type_1", "renames": {},
                    "reason": "The complete declared-language syntax trees are identical after excluding comments and formatting; the selected side's guards, literals, operators, calls and data flow are unchanged."}
        names_a, names_b = binding_nodes(a), binding_nodes(b)
        if len(names_a) != len(names_b):
            raise ValueError("binding_structure_changed")
        renames = {x: y for x, y in zip(names_a, names_b) if x != y}
        # A global text bijection is sound only for these deliberately narrow
        # scopes. In particular, a nested parameter may share a spelling with
        # an outer free variable without being a duplicate declaration.
        for root, names in ((a, names_a), (b, names_b)):
            functions = []
            def scopes(n):
                if n.type in {"function_declaration", "function_expression", "arrow_function", "method_definition", "generator_function", "generator_function_declaration"}:
                    functions.append(n)
                for child in n.children:
                    scopes(child)
            scopes(root)
            if len(functions) != 1:
                raise ValueError("nested_or_multiple_function_scopes_require_review")
            function = functions[0]
            body = function.child_by_field_name("body")
            for n in leaves(root):
                if n.type == "identifier" and n.text.decode() in names:
                    if not function.start_byte <= n.start_byte < function.end_byte:
                        raise ValueError("binding_spelling_used_outside_function")
                    if n.parent.type == "variable_declarator":
                        declaration = n.parent.parent
                        if declaration.parent != body:
                            raise ValueError("nested_block_binding_requires_review")
                    if n.parent.type == "catch_clause":
                        raise ValueError("catch_scope_requires_review")
        # Any non-binding occurrence must remain the same syntax role and map
        # consistently. Function/class names cannot be renamed by this reviewer.
        for root, names in ((a, names_a), (b, names_b)):
            def check(n):
                if n.type in {"function_declaration", "function_expression", "class_declaration", "class"}:
                    name = n.child_by_field_name("name")
                    if name is not None and name.text.decode() in names:
                        raise ValueError("binding_collides_with_function_or_class_name")
                for child in n.children:
                    check(child)
            check(root)
        identifiers = {n.text.decode() for n in leaves(a) if n.type == "identifier"}
        if set(renames.values()) & (identifiers - set(names_a)):
            raise ValueError("rename_captures_free_identifier")
        if signature(a, renames) != signature(b):
            raise ValueError("structural_or_nonlocal_change_requires_review")
        return {"preserved": True, "classification": "type_2", "renames": renames,
            "reason": "The full syntax trees match under the recorded bijection of uniquely declared simple local bindings. No shadowed declarations, free-name capture, function-name changes, reflection, literal/operator/API/guard/control-flow changes or shorthand-property rewrites were accepted. The security delta remains on the same side of the patch."}
    except ValueError as exc:
        return {"preserved": False, "classification": "uncertain", "reason": str(exc)}


def review_record(record, entry):
    side = "vulnerable" if record["expected_status"] == "flagged" else "patched"
    source = entry.vulnerable_function if side == "vulnerable" else entry.patched_function
    delta = "\n".join(difflib.unified_diff(entry.vulnerable_function.splitlines(), entry.patched_function.splitlines(), fromfile="vulnerable", tofile="patched", lineterm=""))
    result = equivalence(source, record["candidate_source"], record["source_language"])
    # A syntactically identical before/after pair cannot establish a security delta.
    distinct = signature(parsed(entry.vulnerable_function, record["source_language"])) != signature(parsed(entry.patched_function, record["source_language"]))
    description = entry.advisory.advisory_description or entry.advisory.advisory_title
    accepted = result["preserved"] and distinct and bool(description) and bool(entry.diagnostic_lines)
    return {"accepted": accepted, "classification": result["classification"], "preservation_reason": result["reason"],
            "binding_renames": result.get("renames", {}), "security_change": description,
            "security_patch": delta, "diagnostic_change": [d.model_dump() for d in entry.diagnostic_lines],
            "package": entry.advisory.package_name, "side": side,
            "source_sha256": digest(source), "candidate_sha256": digest(record["candidate_source"]),
            "scope": "Automated source-and-patch review for syntax-preserving transformations; relies on the reference advisory/patch attribution. No executable exploit test or human validation. Source-reflection behaviour outside the extracted function is outside this review."}
