import re

import tree_sitter
import tree_sitter_javascript

from pipeline.models.parsing import FunctionUnit

_WHITESPACE_RE = re.compile(r"\s+")

FUNCTION_NODE_TYPES = {
    "function_declaration",
    "function_expression",
    "arrow_function",
    "method_definition",
    "generator_function_declaration",
    "generator_function",
}

# A genuine function/method can never be named a JS reserved word. Error recovery on a
# corrupted parse (e.g. Flow/TS syntax this JS-only grammar can't read) can stabilize
# into a self-consistent-looking but wrong tree downstream of the original error, with
# no local ERROR node left to catch -- e.g. `if (__DEV__) { ... }` control flow
# misread as an object literal's shorthand-method syntax, producing a fabricated
# method_definition literally named "if". Reserved words are a cheap, targeted signal
# for exactly that residual case.
_RESERVED_WORDS = {
    "if", "else", "for", "while", "do", "switch", "case", "default", "break",
    "continue", "return", "throw", "try", "catch", "finally", "function", "class",
    "extends", "new", "delete", "typeof", "instanceof", "void", "yield", "await",
    "var", "let", "const", "import", "export", "this", "super", "null", "true",
    "false", "in", "of", "with", "debugger",
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


def get_node_text(node: tree_sitter.Node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte : node.end_byte].decode("utf-8")


def extract_function_units(source: str) -> list[FunctionUnit]:
    tree = parse_source(source)
    source_bytes = source.encode("utf-8")
    units: list[FunctionUnit] = []

    def walk(node: tree_sitter.Node) -> None:
        # `has_error` is true for a node whose own subtree contains a syntax error
        # (e.g. Flow/TS generics like `function act<T>(...)` misread as JSX by this
        # JS-only grammar) -- tree-sitter error-recovers silently rather than raising,
        # and can fabricate bogus nodes (misclassified types, phantom "functions") out
        # of the wreckage. Skip creating a unit from those rather than trusting
        # unreliable extracted text; still recurse into children, since a clean
        # sibling function elsewhere in the same file is unaffected.
        if node.type in FUNCTION_NODE_TYPES and not node.has_error:
            name = _function_name(node)
            if name not in _RESERVED_WORDS:
                units.append(
                    FunctionUnit(
                        name=name,
                        node_type=node.type,
                        start_line=node.start_point[0],
                        end_line=node.end_point[0],
                        start_byte=node.start_byte,
                        end_byte=node.end_byte,
                        source=get_node_text(node, source_bytes),
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


def _find_comment_ranges(node: tree_sitter.Node) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []

    def walk(n: tree_sitter.Node) -> None:
        if n.type == "comment":
            ranges.append((n.start_byte, n.end_byte))
            return
        for child in n.children:
            walk(child)

    walk(node)
    return ranges


def _apply_replacements(source: str, replacements: list[tuple[int, int, str]]) -> str:
    """Applies non-overlapping (start_byte, end_byte, replacement_text) edits to `source`,
    left to right. Passing "" as replacement_text for every range is equivalent to excising
    those ranges."""
    source_bytes = source.encode("utf-8")
    out = bytearray()
    cursor = 0
    for start, end, replacement in sorted(replacements, key=lambda r: (r[0], r[1])):
        out += source_bytes[cursor:start]
        out += replacement.encode("utf-8")
        cursor = end
    out += source_bytes[cursor:]
    return out.decode("utf-8")


def _collapse_line(raw_line: str) -> str:
    return _WHITESPACE_RE.sub(" ", raw_line).strip()


def _collapse_whitespace(source: str) -> list[str]:
    """Collapses interior whitespace runs to a single space per line and drops blank lines."""
    lines: list[str] = []
    for raw_line in source.splitlines():
        collapsed = _collapse_line(raw_line)
        if collapsed:
            lines.append(collapsed)
    return lines


def normalize_source(source: str) -> list[str]:
    """Strips comments (via tree-sitter's `comment` node type, immune to false positives like `//` inside a
    template literal) and collapses whitespace, returning non-empty normalized lines."""
    tree = parse_source(source)
    comment_ranges = _find_comment_ranges(tree.root_node)
    stripped = _apply_replacements(source, [(start, end, "") for start, end in comment_ranges])
    return _collapse_whitespace(stripped)


def get_normalized_node_text(node: tree_sitter.Node, source_bytes: bytes) -> list[str]:
    """Normalized source text for any AST node - whole function, block, or statement."""
    return normalize_source(get_node_text(node, source_bytes))


def normalize_source_with_lines(source: str) -> list[tuple[int, str]]:
    """Like normalize_source, but pairs each surviving normalized line with its raw
    0-indexed line number in `source`. Needed by callers (module 7) that must map an
    alignment index back to DiagnosticLine.vulnerable_line/patched_line, which are raw
    line numbers from an un-normalized difflib diff over source.splitlines() -- while
    normalize_source's own output has no such correspondence (blank lines dropped,
    comments excised entirely).

    Can't reuse normalize_source's "" comment-excision here: a multi-line comment's
    newlines would be deleted along with its text, silently merging the raw lines on
    either side of it once .splitlines() runs on the result. Comment ranges are instead
    replaced with an equivalent run of "\n" characters -- preserving line positions --
    so raw line numbers can be recovered directly from enumerate(stripped.splitlines()).
    """
    tree = parse_source(source)
    comment_ranges = _find_comment_ranges(tree.root_node)
    source_bytes = source.encode("utf-8")
    replacements = [
        (start, end, "\n" * source_bytes[start:end].count(b"\n"))
        for start, end in comment_ranges
    ]
    stripped = _apply_replacements(source, replacements)

    result: list[tuple[int, str]] = []
    for raw_line_no, raw_line in enumerate(stripped.splitlines()):
        collapsed = _collapse_line(raw_line)
        if collapsed:
            result.append((raw_line_no, collapsed))
    return result
