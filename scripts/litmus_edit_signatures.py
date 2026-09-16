"""Litmus test for patch-local edit-signature scoring.

This does not participate in retrieval or production classification.  It treats
the known removed/added diagnostic lines as short fuzzy-search queries and uses
minimum token edit distance to find each query inside the candidate function.

Run from the repository root::

    $env:PYTHONPATH="."
    .venv\Scripts\python.exe scripts\litmus_edit_signatures.py
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
from collections import Counter
from pathlib import Path

from pipeline.controller.parsing import normalize_source


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POSITIVE = ROOT / "eval" / "llm_transformed_positive.jsonl"
DEFAULT_NEGATIVE = ROOT / "eval" / "llm_transformed_negative.jsonl"
DEFAULT_BASELINE = ROOT / "eval" / "llm_transformed_results_regex_sensitive.json"

_KEYWORDS = {
    "async", "await", "break", "case", "catch", "class", "const", "continue",
    "default", "delete", "do", "else", "export", "extends", "false", "finally",
    "for", "function", "if", "import", "in", "instanceof", "let", "new", "null",
    "of", "return", "super", "switch", "this", "throw", "true", "try", "typeof",
    "undefined", "var", "void", "while", "yield",
}
_LEX = re.compile(
    r"""
    /(?:\\.|\[(?:\\.|[^\]\\])*\]|[^/\\\n])+/[A-Za-z]*
    |'(?:\\.|[^'\\])*'
    |"(?:\\.|[^"\\])*"
    |`(?:\\.|[^`\\])*`
    |[A-Za-z_$][A-Za-z0-9_$]*
    |(?:\d+(?:\.\d+)?)
    |===|!==|=>|==|!=|<=|>=|&&|\|\||\?\?|\+\+|--|\+=|-=|\*=|/=|%=|\*\*
    |[^\s]
    """,
    re.VERBOSE,
)
_IDENTIFIER = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")


def _load_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _tokens(source: str) -> list[str]:
    """Role-normalized lexical sequence with security literals preserved."""
    normalized = " ".join(normalize_source(source))
    raw = _LEX.findall(normalized)
    result: list[str] = []
    for index, token in enumerate(raw):
        if not _IDENTIFIER.match(token) or token in _KEYWORDS:
            result.append(token)
            continue
        previous = raw[index - 1] if index else ""
        following = raw[index + 1] if index + 1 < len(raw) else ""
        if previous in {".", "?."}:
            result.append(f"API:{token}")
        elif following == "(":
            result.append(f"CALL:{token}")
        else:
            result.append("ID")
    return result


def _substring_edit_similarity(query: list[str], candidate: list[str]) -> float:
    """Levenshtein similarity against the best candidate substring.

    A zero-initialized first row makes prefixes and suffixes free, exactly as a
    traditional fuzzy substring search. Edits inside the query still cost one.
    """
    if not query:
        return 0.0
    if not candidate:
        return 0.0
    previous = [0] * (len(candidate) + 1)
    for row, query_token in enumerate(query, start=1):
        current = [row]
        for column, candidate_token in enumerate(candidate, start=1):
            current.append(
                min(
                    previous[column] + 1,
                    current[column - 1] + 1,
                    previous[column - 1] + (query_token != candidate_token),
                )
            )
        previous = current
    distance = min(previous)
    return max(0.0, 1.0 - distance / len(query))


def _exclusive_anchors(record: dict) -> tuple[list[list[str]], list[list[str]]]:
    """Return only tokens unique to the removed and added edit sides."""
    removed = [
        token
        for line in record.get("diagnostic_lines", [])
        if line.get("kind") == "removed"
        for token in _tokens(line.get("text") or "")
    ]
    added = [
        token
        for line in record.get("diagnostic_lines", [])
        if line.get("kind") == "added"
        for token in _tokens(line.get("text") or "")
    ]
    vulnerable: list[list[str]] = []
    patched: list[list[str]] = []
    matcher = difflib.SequenceMatcher(a=removed, b=added, autojunk=False)
    for operation, a_start, a_end, b_start, b_end in matcher.get_opcodes():
        if operation in {"delete", "replace"} and a_start < a_end:
            vulnerable.append(removed[a_start:a_end])
        if operation in {"insert", "replace"} and b_start < b_end:
            patched.append(added[b_start:b_end])
    return vulnerable, patched


def _context_anchors(record: dict) -> tuple[list[list[str]], list[list[str]]]:
    """Return complete diagnostic lines, retaining local edit context."""
    vulnerable = [
        tokens
        for line in record.get("diagnostic_lines", [])
        if line.get("kind") == "removed"
        if (tokens := _tokens(line.get("text") or ""))
    ]
    patched = [
        tokens
        for line in record.get("diagnostic_lines", [])
        if line.get("kind") == "added"
        if (tokens := _tokens(line.get("text") or ""))
    ]
    return vulnerable, patched


def _coverage(anchors: list[list[str]], candidate: list[str]) -> float | None:
    if not anchors:
        return None
    weights = [len(anchor) for anchor in anchors]
    return sum(
        _substring_edit_similarity(anchor, candidate) * weight
        for anchor, weight in zip(anchors, weights)
    ) / sum(weights)


def score(record: dict, anchor_mode: str = "context") -> dict:
    candidate = _tokens(record["candidate_source"])
    vulnerable_anchors, patched_anchors = (
        _exclusive_anchors(record)
        if anchor_mode == "exclusive"
        else _context_anchors(record)
    )
    vulnerable = _coverage(vulnerable_anchors, candidate)
    patched = _coverage(patched_anchors, candidate)

    # A pure insertion/deletion has an explicit anchor on only one side. Absence
    # of that anchor is evidence for the opposite side, but is kept visible in
    # the output rather than mixed with global Qv/Qp.
    if vulnerable is None and patched is not None:
        vulnerable = 1.0 - patched
    if patched is None and vulnerable is not None:
        patched = 1.0 - vulnerable
    vulnerable = vulnerable or 0.0
    patched = patched or 0.0
    return {
        "candidate_id": record["candidate_id"],
        "expected_status": record["expected_status"],
        "clone_type": record.get("clone_type"),
        "edit_vulnerable": vulnerable,
        "edit_patched": patched,
        "edit_margin": vulnerable - patched,
    }


def _baseline(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {row["candidate_id"]: row for row in payload.get("results", [])}


def _print_rows(title: str, rows: list[dict]) -> None:
    print(f"\n{title}")
    print("ID      Exp      Clone   Outcome                 E_v    E_p  Margin")
    for row in rows:
        print(
            f"{row['candidate_id']:7s} {row['expected_status']:8s} "
            f"{str(row['clone_type']):7s} {row.get('outcome', 'n/a'):22s} "
            f"{row['edit_vulnerable']:5.3f}  {row['edit_patched']:5.3f}  "
            f"{row['edit_margin']:+6.3f}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--positive", type=Path, default=DEFAULT_POSITIVE)
    parser.add_argument("--negative", type=Path, default=DEFAULT_NEGATIVE)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument(
        "--anchor-mode",
        choices=("context", "exclusive"),
        default="context",
        help="Use full diagnostic context or only tokens unique to each edit side.",
    )
    args = parser.parse_args()

    records = _load_jsonl(args.positive) + _load_jsonl(args.negative)
    baseline = _baseline(args.baseline)
    scored = []
    for record in records:
        item = score(record, anchor_mode=args.anchor_mode)
        item["outcome"] = baseline.get(item["candidate_id"], {}).get("outcome", "n/a")
        scored.append(item)

    directional = Counter()
    for item in scored:
        expected_margin_positive = item["expected_status"] == "flagged"
        margin = item["edit_margin"]
        correct = margin > 0 if expected_margin_positive else margin < 0
        directional["correct" if correct else "wrong_or_tied"] += 1
        if abs(margin) >= 0.10:
            directional["correct_strong" if correct else "wrong_strong"] += 1

    print(
        "Patch-local fuzzy edit-signature litmus "
        f"(anchor mode: {args.anchor_mode}; not production scoring)"
    )
    print(f"Samples: {len(scored)}")
    print(
        "Direction correct: "
        f"{directional['correct']}/{len(scored)} "
        f"({directional['correct'] / len(scored):.1%})"
    )
    print(
        "At |edit margin| >= 0.10: "
        f"{directional['correct_strong']} correct, {directional['wrong_strong']} wrong"
    )

    for expected in ("flagged", "cleared"):
        group = [row for row in scored if row["expected_status"] == expected]
        correct = sum(
            row["edit_margin"] > 0 if expected == "flagged" else row["edit_margin"] < 0
            for row in group
        )
        print(f"  {expected:8s}: {correct}/{len(group)} directionally correct ({correct / len(group):.1%})")

    false_positives = [row for row in scored if row["outcome"] == "false_positive"]
    _print_rows("Current false positives", false_positives)

    wrong_strong = [
        row for row in scored
        if abs(row["edit_margin"]) >= 0.10
        and (
            (row["expected_status"] == "flagged" and row["edit_margin"] <= 0)
            or (row["expected_status"] == "cleared" and row["edit_margin"] >= 0)
        )
    ]
    _print_rows("Confidently wrong directions (risk cases)", wrong_strong)

    focus_ids = {"L090", "LN048"}
    _print_rows("Regex boundary pair", [row for row in scored if row["candidate_id"] in focus_ids])

    positives = [
        row for row in scored
        if row["outcome"] == "true_positive" and row["candidate_id"] != "L090"
    ][:5]
    abstained = [row for row in scored if row["outcome"].startswith("abstained")][:5]
    _print_rows("Representative true positives", positives)
    _print_rows("Representative abstentions", abstained)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
