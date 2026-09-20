import difflib
import re

from provtrail.corpus.integrations.github import fetch_commit, fetch_file_content
from provtrail.corpus.models.commit import ExtractedFunctionPair, GitHubCommitDetail, GitHubCommitFile
from provtrail.corpus.models.corpus import DiagnosticLine
from provtrail.pipeline.controller.parsing import (
    extract_function_units,
    find_enclosing_function,
    is_parse_valid,
    normalize_source_with_lines,
    parse_source,
    source_language,
)
from provtrail.pipeline.models.parsing import FunctionUnit

COMMIT_URL_RE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{7,40})/?$")
HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

JS_EXTENSIONS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")
TEST_PATH_MARKERS = (
    "test/", "tests/", "__tests__/", "spec/", "specs/", "example/", "examples/",
    "fixture/", "fixtures/", "benchmark/", "benchmarks/", "vendor/", "vendors/",
    "third_party/", "node_modules/", "dist/", "build/", "coverage/", ".test.", ".spec.",
)
NON_PRODUCTION_SUFFIXES = (".d.ts", ".min.js", ".min.mjs", ".bundle.js")

# Thresholds for the diff cleanliness filter (automated proxy for the manual review this
# fully-automated pipeline deliberately doesn't have). Calibrated against the axios bootstrap
# commit (7 production files, ~98 changed lines, part of a multi-CVE release) so that a
# legitimate multi-file security fix still passes, while a large unrelated refactor/format
# commit still gets rejected.
MAX_PRODUCTION_FILES = 3
MAX_PRODUCTION_LINES_CHANGED = 150
MAX_PRODUCTION_FUNCTIONS = 5

# Greedy name-fallback matching (anonymous functions) only pairs a pre/post unit if their
# start lines are within this many lines of each other.
MAX_LINE_DRIFT_FOR_POSITIONAL_MATCH = 50


class CleanlinessRejection(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def extract_commit_refs(references: list[str]) -> list[tuple[str, str, str]]:
    """Returns (owner, repo, sha) for every github.com/.../commit/<sha> reference."""
    refs = []
    for url in references:
        m = COMMIT_URL_RE.match(url)
        if m:
            refs.append((m.group(1), m.group(2), m.group(3)))
    return refs


def is_production_js_file(filename: str) -> bool:
    lower = filename.lower().replace("\\", "/")
    if not lower.endswith(JS_EXTENSIONS):
        return False
    if lower.endswith(NON_PRODUCTION_SUFFIXES):
        return False
    return not any(marker in lower for marker in TEST_PATH_MARKERS)


def _substantive_patch_lines(patch: str | None) -> int:
    if not patch:
        return 0
    count = 0
    in_block_comment = False
    for raw in patch.splitlines():
        if not raw.startswith(("+", "-")) or raw.startswith(("+++", "---")):
            continue
        text = raw[1:].strip()
        if in_block_comment:
            if "*/" in text:
                in_block_comment = False
            continue
        if text.startswith("/*"):
            in_block_comment = "*/" not in text
            continue
        if text and not text.startswith(("//", "*")):
            count += 1
    return count


def check_diff_cleanliness(commit: GitHubCommitDetail) -> list[GitHubCommitFile]:
    """Returns the commit's production JS files, or raises CleanlinessRejection."""
    if len(commit.parent_shas) != 1:
        raise CleanlinessRejection("merge_commit")
    production_files = [f for f in commit.files if is_production_js_file(f.filename)]
    if not production_files:
        raise CleanlinessRejection("no_production_js_files")
    if len(production_files) > MAX_PRODUCTION_FILES:
        raise CleanlinessRejection("too_many_files")
    total_changes = sum(_substantive_patch_lines(f.patch) for f in production_files)
    if total_changes > MAX_PRODUCTION_LINES_CHANGED:
        raise CleanlinessRejection("too_many_lines_changed")
    return production_files


def _changed_executable_node_count(source: str, lines: list[int], filename: str) -> int:
    tree = parse_source(source, filename=filename)
    ignored = {"program", "comment", "identifier", "property_identifier", "string", "number"}
    seen: set[tuple[int, int, str]] = set()
    for line in lines:
        point = (line, 0)
        node = tree.root_node.descendant_for_point_range(point, (line, 2**31 - 1))
        while node is not None and (not node.is_named or node.type in ignored):
            node = node.parent
        if node is not None and node.type != "program":
            seen.add((node.start_byte, node.end_byte, node.type))
    return len(seen)


def parse_patch_line_numbers(patch: str) -> tuple[list[int], list[int]]:
    """Returns (pre_lines_0indexed, post_lines_0indexed) touched by a unified diff patch body
    (GitHub's per-file `patch` field: hunks only, no `--- a/file`/`+++ b/file` header lines)."""
    pre_lines: list[int] = []
    post_lines: list[int] = []
    pre_ln: int | None = None
    post_ln: int | None = None
    for line in patch.splitlines():
        m = HUNK_HEADER_RE.match(line)
        if m:
            pre_ln = int(m.group(1))
            post_ln = int(m.group(3))
            continue
        if pre_ln is None or post_ln is None:
            continue
        if not line:
            pre_ln += 1
            post_ln += 1
            continue
        prefix = line[0]
        if prefix == "-":
            pre_lines.append(pre_ln - 1)
            pre_ln += 1
        elif prefix == "+":
            post_lines.append(post_ln - 1)
            post_ln += 1
        elif prefix == "\\":
            continue
        else:
            pre_ln += 1
            post_ln += 1
    return pre_lines, post_lines


def _touched_units(lines: list[int], units: list[FunctionUnit]) -> list[FunctionUnit]:
    seen: set[tuple[int, int]] = set()
    touched: list[FunctionUnit] = []
    for ln in lines:
        unit = find_enclosing_function(ln, units)
        if unit is None:
            continue
        key = (unit.start_byte, unit.end_byte)
        if key not in seen:
            seen.add(key)
            touched.append(unit)
    return touched


def _match_function_units(
    pre_units: list[FunctionUnit], post_units: list[FunctionUnit]
) -> list[tuple[FunctionUnit, FunctionUnit]]:
    """Pairs touched pre/post function units: by name first, then by nearest start-line
    proximity for anonymous functions (heuristic; this pipeline has no manual review gate)."""
    remaining_post = list(post_units)
    pairs: list[tuple[FunctionUnit, FunctionUnit]] = []
    unmatched_pre: list[FunctionUnit] = []

    for pre in pre_units:
        if pre.name:
            match = next((p for p in remaining_post if p.name == pre.name), None)
            if match is not None:
                pairs.append((pre, match))
                remaining_post.remove(match)
                continue
        unmatched_pre.append(pre)

    for pre in unmatched_pre:
        if not remaining_post:
            break
        closest = min(remaining_post, key=lambda p: abs(p.start_line - pre.start_line))
        if abs(closest.start_line - pre.start_line) <= MAX_LINE_DRIFT_FOR_POSITIONAL_MATCH:
            pairs.append((pre, closest))
            remaining_post.remove(closest)

    return pairs


def extract_function_pairs_from_commit(
    owner: str, repo: str, sha: str, session=None
) -> tuple[list[ExtractedFunctionPair], int]:
    """Fetches the commit, applies the diff cleanliness filter, and extracts function-level
    vulnerable/patched pairs for every touched production JS file. Raises CleanlinessRejection
    if the commit fails the filter. Returns (pairs, skipped_identical_count).

    A pre/post unit can be flagged "touched" by _touched_units (a real diff line fell
    within its LINE range) while its extracted node TEXT is byte-identical -- e.g. a
    reformat commit adds a trailing semicolon that sits outside the function node's own
    byte span, or reflows a call chain around an otherwise-untouched nested function.
    Neither side actually changed in a way this method can ever tell apart, so these
    pairs are dropped here rather than stored as a vulnerable/patched pair with no real
    difference -- counted, not silently discarded, per the build plan's attrition-
    reporting requirement.
    """
    commit = fetch_commit(owner, repo, sha, session=session)
    production_files = check_diff_cleanliness(commit)
    if not any(f.deletions for f in production_files):
        raise CleanlinessRejection("added_only")
    parent_sha = commit.parent_shas[0]

    pairs: list[ExtractedFunctionPair] = []
    skipped_identical = 0
    for f in production_files:
        if f.status not in ("modified", "renamed") or not f.patch:
            continue

        pre_path = f.previous_filename or f.filename
        pre_content = fetch_file_content(owner, repo, pre_path, parent_sha, session=session)
        post_content = fetch_file_content(owner, repo, f.filename, sha, session=session)
        if pre_content is None or post_content is None:
            continue

        language = source_language(f.filename)
        if not is_parse_valid(pre_content, filename=pre_path) or not is_parse_valid(
            post_content, filename=f.filename
        ):
            raise CleanlinessRejection("parser_invalid")
        pre_lines, post_lines = parse_patch_line_numbers(f.patch)
        pre_units = extract_function_units(pre_content, filename=pre_path)
        post_units = extract_function_units(post_content, filename=f.filename)

        touched_pre = _touched_units(pre_lines, pre_units)
        touched_post = _touched_units(post_lines, post_units)

        for pre_unit, post_unit in _match_function_units(touched_pre, touched_post):
            if pre_unit.source == post_unit.source:
                skipped_identical += 1
                continue
            diagnostics = compute_diagnostic_lines(
                pre_unit.source, post_unit.source, language=language
            )
            if not diagnostics:
                raise CleanlinessRejection("formatting_only")
            removed = sum(d.kind == "removed" for d in diagnostics)
            added = sum(d.kind == "added" for d in diagnostics)
            if not removed:
                raise CleanlinessRejection("added_only")
            if not added:
                raise CleanlinessRejection("partial_patch")
            removed_nodes = _changed_executable_node_count(pre_content, pre_lines, pre_path)
            added_nodes = _changed_executable_node_count(post_content, post_lines, f.filename)
            if not removed_nodes or not added_nodes:
                raise CleanlinessRejection("no_executable_ast_change")
            pairs.append(
                ExtractedFunctionPair(
                    file_path=f.filename,
                    function_name=pre_unit.name or post_unit.name,
                    vulnerable_function=pre_unit.source,
                    patched_function=post_unit.source,
                    source_language=language,
                    patch_hunk=f.patch,
                    substantive_changed_lines=len(diagnostics),
                )
            )

    if len(pairs) > MAX_PRODUCTION_FUNCTIONS:
        raise CleanlinessRejection("too_many_functions")
    if not pairs:
        raise CleanlinessRejection("identical" if skipped_identical else "partial_patch")
    smallest = min(
        range(len(pairs)),
        key=lambda index: (
            pairs[index].substantive_changed_lines,
            len(pairs[index].vulnerable_function),
            pairs[index].file_path,
            pairs[index].function_name or "",
        ),
    )
    pairs[smallest].is_primary = True
    return pairs, skipped_identical


def compute_diagnostic_lines(
    vulnerable_source: str, patched_source: str, *, language: str | None = None
) -> list[DiagnosticLine]:
    """Plain line diff (not embedding-based alignment) locating which lines differ.

    Comment-only and blank lines are excluded even when difflib flags them as
    changed -- they're narration, not behavior, and module 7 averages its
    verification score across every diagnostic line on a side. A comment added
    alongside one real code line (e.g. explaining why a prototype-pollution guard was
    added) would otherwise count for as much as the code line itself, diluting the one
    line that actually carries the security-relevant difference. Uses
    normalize_source_with_lines's own comment/blank-line filtering (tree-sitter-based,
    so a `//`-looking substring inside a string/regex/template literal is never
    mistaken for a real comment) rather than a separate text-prefix heuristic here.
    """
    vuln_lines = vulnerable_source.splitlines()
    patched_lines = patched_source.splitlines()
    matcher = difflib.SequenceMatcher(a=vuln_lines, b=patched_lines, autojunk=False)

    vuln_significant = {
        ln for ln, _ in normalize_source_with_lines(vulnerable_source, language=language)
    }
    patched_significant = {
        ln for ln, _ in normalize_source_with_lines(patched_source, language=language)
    }

    diagnostics: list[DiagnosticLine] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        if tag in ("delete", "replace"):
            diagnostics.extend(
                DiagnosticLine(kind="removed", vulnerable_line=i, text=vuln_lines[i])
                for i in range(i1, i2) if i in vuln_significant
            )
        if tag in ("insert", "replace"):
            diagnostics.extend(
                DiagnosticLine(kind="added", patched_line=j, text=patched_lines[j])
                for j in range(j1, j2) if j in patched_significant
            )
    return diagnostics
