"""Generate a reproducible 30-case vulnerable-clone candidate subset.

The output is a JSONL benchmark containing positive vulnerable candidates only. Each
record embeds the vulnerable/patched corpus snapshots so the fixture remains auditable
even if the live corpus is rebuilt later.

Run from the repository root:
    PYTHONPATH=. .venv/bin/python scripts/generate_candidate_subset.py
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Callable

import tree_sitter
import tree_sitter_javascript

from corpus.controller.store import load_entries
from corpus.models.corpus import CorpusEntry

OUTPUT_PATH = Path(__file__).resolve().parent.parent / "eval" / "candidate_subset_30.jsonl"

# The base set covers 22 actual corpus function pairs. Eight additional variants
# exercise a second transformation on selected pairs without pretending that repeated
# historical rows are independent vulnerability patterns.
BASE_ROW_IDS = [
    63, 38, 39, 41, 112, 113, 114, 116, 117, 52, 53, 54,
    124, 60, 61, 51, 121, 122, 58, 129, 130, 131,
]

BASE_FAMILIES = {
    63: "alpha_rename+dead_branch",
    38: "alpha_rename+return_split",
    39: "alpha_rename+dead_branch",
    41: "alpha_rename+boolean_expansion",
    112: "alpha_rename+dead_branch",
    113: "alpha_rename+reformat",
    114: "alpha_rename+reformat",
    116: "alpha_rename+return_split",
    117: "dead_branch",
    52: "alpha_rename+statement_reorder",
    53: "alpha_rename+block_rewrite",
    54: "alpha_rename+reformat",
    124: "alpha_rename+return_split",
    60: "alpha_rename+ternary_expansion",
    61: "alpha_rename+dead_branch",
    51: "alpha_rename+dead_branch",
    121: "alpha_rename+return_split",
    122: "alpha_rename+return_split",
    58: "alpha_rename+dead_branch",
    129: "alpha_rename+dead_branch",
    130: "alpha_rename+return_split",
    131: "alpha_rename+return_split",
}

EXTRA_VARIANTS = [
    (63, "alpha_rename+reformat"),
    (38, "alpha_rename+dead_branch"),
    (39, "alpha_rename+return_split"),
    (41, "alpha_rename+dead_branch"),
    (112, "alpha_rename+reformat"),
    (53, "alpha_rename+dead_branch"),
    (60, "alpha_rename+return_split"),
    (52, "alpha_rename+dead_branch"),
]

MAPPINGS: dict[int, dict[str, str]] = {
    63: {
        "options": "requestOptions",
        "configProxy": "proxySettings",
        "location": "requestTarget",
        "proxy": "proxyValue",
        "proxyUrl": "proxyAddress",
        "validProxyAuth": "hasProxyCredentials",
        "base64": "encodedCredentials",
        "proxyHost": "targetProxyHost",
        "redirectOptions": "nextRedirect",
    },
    38: {"url": "requestUrl", "config": "requestConfig", "method": "httpMethod"},
    39: {
        "url": "requestUrl",
        "params": "queryParams",
        "options": "serializationOptions",
        "_encode": "encoder",
        "serializeFn": "serializer",
        "serializedParams": "encodedQuery",
        "hashmarkIndex": "fragmentIndex",
    },
    41: {"hostname": "hostName"},
    112: {
        "chunk": "dataPiece",
        "responseBuffer": "bufferedChunks",
        "totalResponseBytes": "bytesReceived",
        "config": "requestConfig",
        "rejected": "requestRejected",
    },
    113: {"rejected": "requestRejected", "config": "requestConfig", "stream": "incomingStream"},
    114: {
        "responseBuffer": "bufferedChunks",
        "responseData": "bodyData",
        "config": "requestConfig",
        "response": "httpResponse",
        "resolve": "resolveRequest",
        "reject": "rejectRequest",
        "err": "caughtError",
    },
    116: {
        "data": "payload",
        "transitional": "transition",
        "silentJSONParsing": "allowInvalidJson",
        "forcedJSONParsing": "forceJson",
        "strictJSONParsing": "strictJson",
    },
    117: {},
    52: {
        "message": "errorMessage",
        "code": "errorCode",
        "config": "requestConfig",
        "request": "requestObject",
        "response": "responseObject",
    },
    53: {
        "value": "inputValue",
        "path": "pathSegments",
        "el": "itemValue",
        "key": "propertyName",
        "result": "shouldVisit",
    },
    54: {"el": "itemValue", "key": "propertyName", "result": "shouldVisit"},
    124: {"url": "candidateUrl"},
    60: {"value": "headerValue"},
    61: {
        "options": "requestOptions",
        "configProxy": "proxySettings",
        "location": "requestTarget",
        "proxy": "proxyValue",
        "proxyUrl": "proxyAddress",
        "base64": "encodedCredentials",
        "redirectOptions": "nextRedirect",
    },
    51: {"redirectOptions": "nextRedirectOptions"},
    121: {"config": "requestConfig", "fullPath": "completePath"},
    122: {"baseURL": "baseAddress", "requestedURL": "requestedAddress"},
    58: {
        "options": "configOptions",
        "schema": "validators",
        "allowUnknown": "permitUnknown",
        "keys": "optionNames",
        "i": "index",
        "opt": "optionName",
        "validator": "check",
        "value": "optionValue",
        "result": "validationResult",
    },
    129: {"u": "escapedAddress"},
    130: {"url": "targetUrl", "loc": "locationValue"},
    131: {
        "url": "targetUrl",
        "loc": "locationValue",
        "lowerLoc": "lowerLocation",
        "encodedUrl": "encodedLocation",
        "parsedUrl": "parsedLocation",
        "parsedEncodedUrl": "parsedEncodedLocation",
        "e": "parseError",
    },
}

_parser = tree_sitter.Parser(tree_sitter.Language(tree_sitter_javascript.language()))


def _replace_ranges(source: str, replacements: list[tuple[int, int, str]]) -> str:
    source_bytes = source.encode("utf-8")
    result = bytearray()
    cursor = 0
    for start, end, replacement in sorted(replacements, key=lambda item: item[0]):
        result.extend(source_bytes[cursor:start])
        result.extend(replacement.encode("utf-8"))
        cursor = end
    result.extend(source_bytes[cursor:])
    return result.decode("utf-8")


def rename_identifiers(source: str, mapping: dict[str, str]) -> str:
    if not mapping:
        return source

    tree = _parser.parse(source.encode("utf-8"))
    replacements: list[tuple[int, int, str]] = []

    def walk(node: tree_sitter.Node) -> None:
        if node.type == "identifier":
            name = node.text.decode("utf-8")
            if name in mapping:
                replacements.append((node.start_byte, node.end_byte, mapping[name]))
        elif node.type in {"shorthand_property_identifier", "shorthand_property_identifier_pattern"}:
            # Preserve object shape when renaming a shorthand value, e.g.
            # `{ proxy }` must become `{ proxy: proxyValue }`, not `{ proxyValue }`.
            name = node.text.decode("utf-8")
            if name in mapping:
                replacements.append(
                    (node.start_byte, node.end_byte, f"{name}: {mapping[name]}")
                )
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return _replace_ranges(source, replacements)


def insert_dead_branch(source: str) -> str:
    opening = source.find("{")
    if opening == -1:
        raise ValueError("Could not find function body opening brace")
    insertion = "\n    if (false) {\n      void 0;\n    }\n"
    return source[: opening + 1] + insertion + source[opening + 1 :]


def split_first_return(source: str) -> str:
    tree = _parser.parse(source.encode("utf-8"))
    return_node: tree_sitter.Node | None = None

    def walk(node: tree_sitter.Node) -> None:
        nonlocal return_node
        if return_node is not None:
            return
        if node.type == "return_statement":
            return_node = node
            return
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    if return_node is None:
        raise ValueError("No return statement available for return-split transformation")

    source_bytes = source.encode("utf-8")
    original = source_bytes[return_node.start_byte:return_node.end_byte].decode("utf-8")
    expression = original[len("return"):].strip()
    if expression.endswith(";"):
        expression = expression[:-1].rstrip()

    before = source[:return_node.start_byte]
    line_prefix = before.rsplit("\n", 1)[-1]
    indent = line_prefix[: len(line_prefix) - len(line_prefix.lstrip())]
    replacement = (
        f"const __clone_result = {expression};\n"
        f"{indent}return __clone_result;"
    )
    return _replace_ranges(source, [(return_node.start_byte, return_node.end_byte, replacement)])


def rewrite_boolean_return(source: str) -> str:
    old = "return hostName === 'localhost' || hostName === '::1' || isLoopbackIPv4(hostName);"
    new = (
        "if (hostName === 'localhost' || hostName === '::1') {\n"
        "    return true;\n"
        "  }\n"
        "  return isLoopbackIPv4(hostName);"
    )
    if old not in source:
        raise ValueError("Expected loopback return was not found")
    return source.replace(old, new, 1)


def rewrite_ternary_return(source: str) -> str:
    old = (
        "return utils.isArray(headerValue)\n"
        "    ? headerValue.map(normalizeValue)\n"
        "    : String(headerValue).replace(/[\\r\\n]+$/, '');"
    )
    new = (
        "if (utils.isArray(headerValue)) {\n"
        "    return headerValue.map(normalizeValue);\n"
        "  }\n"
        "  return String(headerValue).replace(/[\\r\\n]+$/, '');"
    )
    if old not in source:
        raise ValueError("Expected normalizeValue ternary was not found")
    return source.replace(old, new, 1)


def rewrite_single_line_if(source: str) -> str:
    old = "if (utils.isUndefined(inputValue)) return;"
    new = "if (utils.isUndefined(inputValue)) {\n      return;\n    }"
    if old not in source:
        raise ValueError("Expected single-line guard was not found")
    return source.replace(old, new, 1)


def reformat_source(source: str) -> str:
    lines = source.splitlines()
    reformatted: list[str] = []
    for index, line in enumerate(lines):
        if index == 0 or not line.strip():
            reformatted.append(line)
            continue
        indent_width = len(line) - len(line.lstrip())
        reformatted.append(" " * max(0, indent_width - 2) + line.lstrip())
    return "\n".join(reformatted) + ("\n" if source.endswith("\n") else "")


def reorder_constructor_assignments(source: str) -> str:
    first = "this.name = 'AxiosError';\n      this.isAxiosError = true;"
    second = "this.isAxiosError = true;\n      this.name = 'AxiosError';"
    if first in source:
        return source.replace(first, second, 1)
    first = "this.name = 'AxiosError';\n      this.isAxiosError = true;"
    if first in source:
        return source.replace(first, second, 1)
    raise ValueError("Expected independent constructor assignments were not found")


def apply_transformation(source: str, rowid: int, family: str) -> str:
    transformed = rename_identifiers(source, MAPPINGS.get(rowid, {}))

    if "dead_branch" in family:
        transformed = insert_dead_branch(transformed)
    if "return_split" in family:
        transformed = split_first_return(transformed)
    if "boolean_expansion" in family:
        transformed = rewrite_boolean_return(transformed)
    if "ternary_expansion" in family:
        transformed = rewrite_ternary_return(transformed)
    if "block_rewrite" in family:
        transformed = rewrite_single_line_if(transformed)
    if "statement_reorder" in family:
        transformed = reorder_constructor_assignments(transformed)
    if "reformat" in family:
        transformed = reformat_source(transformed)

    return transformed


def validate_candidate(source: str, original: str) -> None:
    if source == original:
        raise ValueError("Transformation produced byte-identical source")
    tree = _parser.parse(source.encode("utf-8"))
    if tree.root_node.has_error:
        # Class methods are stored by the corpus without their surrounding class.
        # Validate those snippets in the same synthetic wrapper used by hierarchy.py.
        wrapped = "class __CandidateWrapper {\n" + source + "\n}\n"
        wrapped_tree = _parser.parse(wrapped.encode("utf-8"))
        if wrapped_tree.root_node.has_error:
            raise ValueError("Transformed candidate contains a Tree-sitter parse error")


def digest(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def entry_key(entry: CorpusEntry) -> dict[str, str | None]:
    return {
        "ghsa_id": entry.ghsa_id,
        "cve_id": entry.cve_id,
        "fix_commit_sha": entry.fix_commit_sha,
        "repo": entry.repo,
        "file_path": entry.file_path,
        "function_name": entry.function_name,
    }


def make_record(
    candidate_id: str,
    entry: CorpusEntry,
    candidate_source: str,
    family: str,
    generation_method: str,
) -> dict:
    return {
        "candidate_id": candidate_id,
        "expected_status": "flagged",
        "generation_method": generation_method,
        "transformation_family": family,
        "corpus_entry": entry_key(entry),
        "package_name": entry.package_name,
        "ecosystem": entry.ecosystem,
        "osv_id": entry.osv_id,
        "affected_versions": entry.affected_versions,
        "fixed_versions": entry.fixed_versions,
        "severity": entry.severity,
        "cwes": [c.model_dump() for c in entry.cwes],
        "osv_confirmed": entry.osv_confirmed,
        "vulnerable_source_sha256": digest(entry.vulnerable_function),
        "patched_source_sha256": digest(entry.patched_function),
        "vulnerable_function": entry.vulnerable_function,
        "patched_function": entry.patched_function,
        "diagnostic_lines": [line.model_dump() for line in entry.diagnostic_lines],
        "candidate_source": candidate_source,
    }


def main() -> None:
    entries = load_entries()
    by_rowid = {index + 1: entry for index, entry in enumerate(entries)}
    missing = [rowid for rowid in BASE_ROW_IDS if rowid not in by_rowid]
    if missing:
        raise RuntimeError(f"Corpus row IDs are missing: {missing}")

    records: list[dict] = []
    seen_keys: set[tuple[int, str]] = set()

    for rowid in BASE_ROW_IDS:
        entry = by_rowid[rowid]
        family = BASE_FAMILIES.get(rowid, "alpha_rename")
        candidate = apply_transformation(entry.vulnerable_function, rowid, family)
        validate_candidate(candidate, entry.vulnerable_function)
        records.append(
            make_record(
                f"C{len(records) + 1:02d}",
                entry,
                candidate,
                family,
                "deterministic_ast_identifier_transform",
            )
        )
        seen_keys.add((rowid, family))

    for rowid, family in EXTRA_VARIANTS:
        if (rowid, family) in seen_keys:
            raise RuntimeError(f"Duplicate candidate specification: {(rowid, family)}")
        entry = by_rowid[rowid]
        candidate = apply_transformation(entry.vulnerable_function, rowid, family)
        validate_candidate(candidate, entry.vulnerable_function)
        records.append(
            make_record(
                f"C{len(records) + 1:02d}",
                entry,
                candidate,
                family,
                "deterministic_ast_identifier_transform",
            )
        )
        seen_keys.add((rowid, family))

    if len(records) != 30:
        raise AssertionError(f"Expected 30 records, generated {len(records)}")

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(f"Wrote {len(records)} candidates to {OUTPUT_PATH}")
    families: dict[str, int] = {}
    for record in records:
        family = record["transformation_family"]
        families[family] = families.get(family, 0) + 1
    for family, count in sorted(families.items()):
        print(f"  {family}: {count}")


if __name__ == "__main__":
    main()
