"""Run a fixed 100-positive, clone-only ProvTrail/jscpd comparison.

The first 30 samples are the original pilot. New samples are selected without
looking at tool outcomes, with 25 distinct origins per clone-intent label and
12 JS / 13 TS samples per label. No vulnerability verdict is scored.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

import tree_sitter
import tree_sitter_javascript
import tree_sitter_typescript

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval.comparison import read_jsonl
from scripts.compare_clone_30 import run_jscpd_pool, run_provtrail
from scripts.run_jscpd_clone_30 import SETTINGS, samples as pilot_samples

SOURCE = ROOT / "eval" / "llm_transformed_expanded_positive.jsonl"
OUTPUT = ROOT / "eval" / "comparison_raw" / "jscpd_clone_100"
TYPES = ("type_1", "type_2", "type_3", "type_4")
LANGUAGE_TARGETS = {"javascript": 12, "typescript": 13}
ONE_LINE_SETTING = (
    "one_line_20_tokens", 1, 20,
    ("--ignore-identifiers", "--max-gap-lines", "2", "--similarity", "0.7"),
)


def origin_key(record: dict) -> tuple:
    origin = record["corpus_entry"]
    return (
        origin["ghsa_id"], origin["fix_commit_sha"],
        origin["file_path"], origin.get("function_name") or "",
    )


def identifier_rename(source: str, language: str) -> str | None:
    """Rename one declared parameter/local, preserving shorthand object keys."""
    grammar = (
        tree_sitter_javascript.language() if language == "javascript"
        else tree_sitter_typescript.language_typescript()
    )
    parser = tree_sitter.Parser(tree_sitter.Language(grammar))
    source_bytes = source.encode("utf-8")
    tree = parser.parse(source_bytes)
    declared: list[str] = []

    def first_identifier(node) -> str | None:
        if node.type == "identifier":
            return source_bytes[node.start_byte:node.end_byte].decode("utf-8")
        if node.type == "type_annotation":
            return None
        for child in node.named_children:
            found = first_identifier(child)
            if found:
                return found
        return None

    def find_declarations(node) -> None:
        if node.type == "formal_parameters":
            for child in node.named_children:
                found = first_identifier(child)
                if found:
                    declared.append(found)
        elif node.type == "variable_declarator":
            name = node.child_by_field_name("name")
            if name is not None and name.type == "identifier":
                declared.append(source_bytes[name.start_byte:name.end_byte].decode("utf-8"))
        for child in node.named_children:
            find_declarations(child)

    find_declarations(tree.root_node)
    for name in dict.fromkeys(declared):
        if name.startswith("__clone_"):
            continue
        replacement = f"__clone_{name}"
        edits = []

        def find_edits(node) -> None:
            if node.type in {
                "identifier", "shorthand_property_identifier",
                "shorthand_property_identifier_pattern",
            } and source_bytes[node.start_byte:node.end_byte].decode("utf-8") == name:
                value = replacement
                if node.type.startswith("shorthand_property"):
                    value = f"{name}: {replacement}"
                edits.append((node.start_byte, node.end_byte, value))
                return
            for child in node.named_children:
                find_edits(child)

        find_edits(tree.root_node)
        if len(edits) < 2:
            continue
        changed = source_bytes
        for start, end, value in reversed(edits):
            changed = changed[:start] + value.encode("utf-8") + changed[end:]
        candidate = changed.decode("utf-8")
        # Detached class methods are valid inside a class wrapper.
        if not parser.parse(changed).root_node.has_error or not parser.parse(
            ("class __CloneWrapper {\n" + candidate + "\n}").encode("utf-8")
        ).root_node.has_error:
            return candidate
    return None


def samples_100() -> list[dict]:
    chosen = pilot_samples()
    used = {origin_key(sample["fixture_record"]) for sample in chosen}
    rows = sorted(
        read_jsonl(SOURCE),
        key=lambda row: (origin_key(row), row["clone_type"], row["candidate_source_sha256"]),
    )
    for clone_type in TYPES:
        counts = Counter(
            sample["language"] for sample in chosen if sample["clone_type"] == clone_type
        )
        for language, target in LANGUAGE_TARGETS.items():
            for record in rows:
                if counts[language] >= target:
                    break
                key = origin_key(record)
                if key in used or record["source_language"] != language:
                    continue
                if clone_type in {"type_3", "type_4"} and record["clone_type"] != clone_type:
                    continue
                reference = record["vulnerable_function"]
                candidate = (
                    reference if clone_type == "type_1" else
                    identifier_rename(reference, language) if clone_type == "type_2" else
                    record["candidate_source"]
                )
                if candidate is None or (clone_type == "type_2" and candidate == reference):
                    continue
                sample_id = f"{clone_type}-E{len(chosen) + 1:03d}"
                chosen.append({
                    "sample_id": sample_id, "clone_type": clone_type,
                    "language": language, "origin": record["corpus_entry"],
                    "reference": reference, "candidate": candidate,
                    "fixture_record": record,
                    "reference_sha256": hashlib.sha256(reference.encode()).hexdigest(),
                    "candidate_sha256": hashlib.sha256(candidate.encode()).hexdigest(),
                    "selection_source": "expanded_positive_fixture",
                })
                used.add(key)
                counts[language] += 1
            if counts[language] != target:
                raise ValueError(f"Only {counts[language]}/{target} {language} {clone_type} samples")
    if len(chosen) != 100 or len(used) != 100:
        raise AssertionError("expected 100 samples from 100 distinct origins")
    return chosen


def run_jscpd_by_origin(
    jscpd: Path, chosen: list[dict], *, min_lines: int = 3,
    min_tokens: int = 20, label: str = "paired",
) -> list[dict]:
    """Avoid global duplicate suppression by scanning each origin separately."""
    rows = []
    for sample in chosen:
        ext = ".js" if sample["language"] == "javascript" else ".ts"
        run_root = OUTPUT / label / sample["sample_id"]
        input_root = run_root / "input"
        input_root.mkdir(parents=True, exist_ok=True)
        for name, source in (
            ("vulnerable", sample["reference"]),
            ("patched", sample["fixture_record"]["patched_function"]),
            ("candidate", sample["candidate"]),
        ):
            (input_root / f"{name}{ext}").write_text(source, encoding="utf-8")
        command = [
            str(jscpd), "--min-lines", str(min_lines), "--min-tokens", str(min_tokens),
            "--ignore-identifiers", "--max-gap-lines", "2", "--similarity", "0.7",
            "--reporters", "json", "--output", str(run_root / "report"),
            "--format", sample["language"], "--mode", "weak", "--silent",
            str(input_root),
        ]
        completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        if completed.returncode:
            raise RuntimeError(f"jscpd paired scan failed for {sample['sample_id']}: {completed.stderr}")
        report = json.loads((run_root / "report" / "jscpd-report.json").read_text(encoding="utf-8"))
        matched_sides = set()
        for clone in report.get("duplicates", []):
            a = Path(clone["firstFile"]["name"]).name
            b = Path(clone["secondFile"]["name"]).name
            if a == f"candidate{ext}" and b in {f"vulnerable{ext}", f"patched{ext}"}:
                matched_sides.add(b.removesuffix(ext))
            elif b == f"candidate{ext}" and a in {f"vulnerable{ext}", f"patched{ext}"}:
                matched_sides.add(a.removesuffix(ext))
        rows.append({
            "sample_id": sample["sample_id"], "clone_type": sample["clone_type"],
            "matched": bool(matched_sides), "matched_sides": sorted(matched_sides),
        })
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--jscpd", type=Path, required=True)
    parser.add_argument("--paired-only", action="store_true", help="append paired jscpd results to an existing run")
    parser.add_argument("--one-line-only", action="store_true", help="append 1-line/20-token jscpd sensitivity results")
    args = parser.parse_args()
    version = subprocess.run(
        [str(args.jscpd), "--version"], cwd=ROOT, capture_output=True,
        text=True, check=True,
    ).stdout.strip()
    if version != "jscpd 5.3.0":
        raise ValueError(f"expected jscpd 5.3.0, got {version!r}")
    chosen = samples_100()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    if args.one_line_only:
        path = OUTPUT / "contrast.json"
        output = json.loads(path.read_text(encoding="utf-8"))
        extra_rows, extra_timings = run_jscpd_pool(
            args.jscpd, chosen, OUTPUT,
            settings=(ONE_LINE_SETTING,),
        )
        output["jscpd"] = [
            row for row in output["jscpd"] if row["setting"] != "one_line_20_tokens"
        ] + extra_rows
        output["timings_seconds"]["jscpd_scan"].update(extra_timings)
        output["jscpd_paired_one_line_20_tokens"] = run_jscpd_by_origin(
            args.jscpd, chosen, min_lines=1, min_tokens=20,
            label="paired_one_line_20_tokens",
        )
        path.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
        print("jscpd pooled 1 line / 20 tokens", dict(Counter(
            row["clone_type"] for row in extra_rows if row["any_reference"]
        )))
        print("jscpd paired 1 line / 20 tokens", dict(Counter(
            row["clone_type"] for row in output["jscpd_paired_one_line_20_tokens"] if row["matched"]
        )))
        return 0
    if args.paired_only:
        path = OUTPUT / "contrast.json"
        output = json.loads(path.read_text(encoding="utf-8"))
        output["jscpd_paired_near_miss"] = run_jscpd_by_origin(args.jscpd, chosen)
        path.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
        print("jscpd paired near_miss", dict(Counter(
            row["clone_type"] for row in output["jscpd_paired_near_miss"] if row["matched"]
        )))
        return 0
    manifest = [{
        "sample_id": sample["sample_id"], "clone_type": sample["clone_type"],
        "language": sample["language"], "origin": sample["origin"],
        "reference_sha256": hashlib.sha256(sample["reference"].encode()).hexdigest(),
        "candidate_sha256": hashlib.sha256(sample["candidate"].encode()).hexdigest(),
    } for sample in chosen]
    (OUTPUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    jscpd_rows, jscpd_timings = run_jscpd_pool(
        args.jscpd, chosen, OUTPUT, settings=(*SETTINGS, ONE_LINE_SETTING)
    )
    jscpd_paired = run_jscpd_by_origin(args.jscpd, chosen)
    jscpd_paired_one_line = run_jscpd_by_origin(
        args.jscpd, chosen, min_lines=1, min_tokens=20,
        label="paired_one_line_20_tokens",
    )
    provtrail_rows, provtrail_timings = run_provtrail(chosen)
    output = {
        "schema": "clone_detection_100_v1", "sample_count": 100,
        "reference_pool_origins": 100, "jscpd_version": "5.3.0",
        "jscpd": jscpd_rows, "provtrail": provtrail_rows,
        "jscpd_paired_near_miss": jscpd_paired,
        "jscpd_paired_one_line_20_tokens": jscpd_paired_one_line,
        "timings_seconds": {"jscpd_scan": jscpd_timings, "provtrail": provtrail_timings},
    }
    (OUTPUT / "contrast.json").write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    for setting in ("default", "renamed", "near_miss", "one_line_20_tokens"):
        print("jscpd", setting, dict(Counter(
            row["clone_type"] for row in jscpd_rows
            if row["setting"] == setting and row["any_reference"]
        )))
    print("provtrail", dict(Counter(
        row["clone_type"] for row in provtrail_rows if row["any_reference"]
    )))
    print("jscpd paired near_miss", dict(Counter(
        row["clone_type"] for row in jscpd_paired if row["matched"]
    )))
    print("jscpd paired 1 line / 20 tokens", dict(Counter(
        row["clone_type"] for row in jscpd_paired_one_line if row["matched"]
    )))
    print("Saved", OUTPUT / "contrast.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
