import re

import tree_sitter
import tree_sitter_javascript

try:
    import tree_sitter_typescript
except ImportError:  # Existing JS-only installs remain usable until dependencies are refreshed.
    tree_sitter_typescript = None

from provtrail.pipeline.models.parsing import FunctionUnit

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

SUPPORTED_SOURCE_EXTENSIONS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")
TYPESCRIPT_EXTENSIONS = (".ts", ".tsx", ".mts", ".cts")

_languages: dict[str, tree_sitter.Language] = {}
_parsers: dict[str, tree_sitter.Parser] = {}


def _typescript_fallback(source: str, *, preserve_width: bool) -> str:
    """Conservative fallback used only when the optional TS grammar is unavailable."""
    patterns = (
        r"\b(?:interface|type)\s+[A-Za-z_$][\w$]*(?:\s*<[^>\n]+>)?\s*(?:=\s*[^;\n]+;?|\{[^{}]*\})",
        r"(?<=[A-Za-z0-9_$])<\s*[A-Za-z_$][^>\n]*>(?=\s*\()",
        r":\s*(?:string|number|boolean|unknown|any|never|void|object|[A-Z_$][\w$]*)(?:\s*<[^;=(){}\n]+>)?(?:\[\])?(?:\s*\|\s*[A-Za-z_$][\w$]*(?:\[\])?)*(?=\s*[,)=;{}])",
        r"\s+as\s+(?:const|[A-Za-z_$][\w$]*(?:\s*<[^;,){}\n]+>)?(?:\[\])?)(?=\s*[,;)}\]])",
        r"\b(?:public|private|protected|readonly|abstract|declare)\s+",
    )

    def replacement(match: re.Match) -> str:
        if not preserve_width:
            return ""
        return "".join("\n" if char == "\n" else " " for char in match.group(0))

    output = source
    for pattern in patterns:
        output = re.sub(pattern, replacement, output, flags=re.DOTALL)
    return output



def source_language(filename: str | None = None, language: str | None = None) -> str:
    if language:
        normalized = language.lower()
        if normalized in {"typescript", "tsx"}:
            return normalized
        return "javascript"
    suffix = (filename or "").lower()
    if suffix.endswith(".tsx"):
        return "tsx"
    if suffix.endswith(TYPESCRIPT_EXTENSIONS):
        return "typescript"
    return "javascript"


def _get_parser(language: str = "javascript") -> tree_sitter.Parser:
    language = source_language(language=language)
    if language not in _parsers:
        if language == "javascript":
            capsule = tree_sitter_javascript.language()
        else:
            if tree_sitter_typescript is None:
                # Keep byte offsets aligned with the native source. This fallback is
                # deliberately narrower than the real grammar and never changes the
                # language label used by matching policy.
                return _get_parser("javascript")
            capsule = (
                tree_sitter_typescript.language_tsx()
                if language == "tsx"
                else tree_sitter_typescript.language_typescript()
            )
        grammar = tree_sitter.Language(capsule)
        _languages[language] = grammar
        _parsers[language] = tree_sitter.Parser(grammar)
    return _parsers[language]


def parse_source(
    source: str, *, filename: str | None = None, language: str | None = None
) -> tree_sitter.Tree:
    selected = source_language(filename, language)
    parse_input = (
        _typescript_fallback(source, preserve_width=True)
        if selected != "javascript" and tree_sitter_typescript is None
        else source
    )
    return _get_parser(selected).parse(parse_input.encode("utf-8"))


def is_parse_valid(source: str, *, filename: str | None = None, language: str | None = None) -> bool:
    try:
        return not parse_source(source, filename=filename, language=language).root_node.has_error
    except (RuntimeError, ValueError):
        return False


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


def extract_function_units(
    source: str, *, filename: str | None = None, language: str | None = None
) -> list[FunctionUnit]:
    selected_language = source_language(filename, language)
    tree = parse_source(source, language=selected_language)
    source_bytes = source.encode("utf-8")
    units: list[FunctionUnit] = []

    def walk(node: tree_sitter.Node) -> None:
        # `has_error` is true for a node whose own subtree contains a syntax error
        # (e.g. Flow/TS generics like `function act<T>(...)` misread as JSX by this
        # JS-only grammar) -- tree-sitter error-recovers silently rather than raising,
        # and can fabricate bogus nodes (misclassified types, phantom "functions") out
        # of the wreckage. Skip creating a unit from those rather than trusting
    # unreliable extracted text. Still recurse into children, since a clean
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
                        language=selected_language,
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


def normalize_source(source: str, *, language: str | None = None) -> list[str]:
    """Strips comments (via tree-sitter's `comment` node type, immune to false positives like `//` inside a
    template literal) and collapses whitespace, returning non-empty normalized lines."""
    tree = parse_source(source, language=language)
    comment_ranges = _find_comment_ranges(tree.root_node)
    stripped = _apply_replacements(source, [(start, end, "") for start, end in comment_ranges])
    return _collapse_whitespace(stripped)


def normalize_source_with_lines(
    source: str, *, language: str | None = None
) -> list[tuple[int, str]]:
    """Normalize source while retaining raw line numbers for corpus diagnostics.

    Preserve comment newlines so diagnostic lines still point into the original
    vulnerable and patched source strings.
    """
    tree = parse_source(source, language=language)
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
