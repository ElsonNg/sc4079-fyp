import tree_sitter
import tree_sitter_javascript

from pipeline.models.parsing import FunctionUnit

FUNCTION_NODE_TYPES = {
    "function_declaration",
    "function_expression",
    "arrow_function",
    "method_definition",
    "generator_function_declaration",
    "generator_function",
}

_language: tree_sitter.Language | None = None
_parser: tree_sitter.Parser | None = None


def _get_parser() -> tree_sitter.Parser:
    global _language, _parser
    if _parser is None:
        _language = tree_sitter.Language(tree_sitter_javascript.language())
        _parser = tree_sitter.Parser(_language)
    return _parser


def parse_source(source: str) -> tree_sitter.Tree:
    return _get_parser().parse(source.encode("utf-8"))


def _function_name(node: tree_sitter.Node) -> str | None:
    name_node = node.child_by_field_name("name")
    if name_node is not None:
        return name_node.text.decode("utf-8")

    parent = node.parent
    if parent is None:
        return None
    if parent.type == "variable_declarator":
        name_node = parent.child_by_field_name("name")
    elif parent.type == "pair":
        name_node = parent.child_by_field_name("key")
    elif parent.type == "assignment_expression":
        name_node = parent.child_by_field_name("left")
    else:
        return None
    return name_node.text.decode("utf-8") if name_node is not None else None


def extract_function_units(source: str) -> list[FunctionUnit]:
    tree = parse_source(source)
    source_bytes = source.encode("utf-8")
    units: list[FunctionUnit] = []

    def walk(node: tree_sitter.Node) -> None:
        if node.type in FUNCTION_NODE_TYPES:
            units.append(
                FunctionUnit(
                    name=_function_name(node),
                    node_type=node.type,
                    start_line=node.start_point[0],
                    end_line=node.end_point[0],
                    start_byte=node.start_byte,
                    end_byte=node.end_byte,
                    source=source_bytes[node.start_byte : node.end_byte].decode("utf-8"),
                )
            )
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return units


def find_enclosing_function(
    line: int, units: list[FunctionUnit]
) -> FunctionUnit | None:
    """`line` is 0-indexed. Returns the innermost function unit containing it, or None."""
    candidates = [u for u in units if u.start_line <= line <= u.end_line]
    if not candidates:
        return None
    return min(candidates, key=lambda u: u.end_line - u.start_line)
