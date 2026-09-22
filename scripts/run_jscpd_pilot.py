"""Run a small, paired jscpd probe against vulnerable reference functions."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval.comparison import read_jsonl
from provtrail.pipeline.controller.parsing import extract_function_units

PAIRS = (("CMP0003", "CMP0004"), ("CMP0015", "CMP0016"), ("CMP0171", "CMP0172"))
OUTPUT_ROOT = ROOT / "eval" / "comparison_raw" / "jscpd_pilot"


def _reference(case: dict, truth: dict) -> str:
    path = ROOT / case["input"]["workspace_root"] / case["input"]["target_path"]
    source = path.read_text(encoding="utf-8")
    matching = [
        unit for unit in extract_function_units(source, filename=str(path))
        if hashlib.sha256(unit.source.encode("utf-8")).hexdigest() == truth["target_source_sha256"]
    ]
    if not matching:
        matching = [
            unit for unit in extract_function_units(source, filename=str(path))
            if unit.name == truth["target_function_name"]
            and unit.start_line + 1 <= truth["target_start_line"]
            and unit.end_line + 1 >= truth["target_end_line"]
        ]
    if len(matching) != 1:
        raise ValueError(f"expected one vulnerable reference for {case['case_id']}; got {len(matching)}")
    return matching[0].source


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--jscpd", type=Path, required=True)
    args = parser.parse_args()
    cases = {row["case_id"]: row for row in read_jsonl(ROOT / "eval" / "comparison_50_cases.jsonl")}
    truths = {row["case_id"]: row for row in read_jsonl(ROOT / "eval" / "comparison_50_ground_truth.jsonl")}
    output = []
    for vulnerable_id, patched_id in PAIRS:
        real_id = f"CMP{int(vulnerable_id[3:]) - 2:04d}"
        reference = _reference(cases[real_id], truths[real_id])
        for case_id in (f"EXACT_{real_id}", vulnerable_id, patched_id):
            case = cases[real_id if case_id.startswith("EXACT_") else case_id]
            language = case["source_language"]
            extension = ".ts" if language == "typescript" else ".js"
            candidate_source = reference if case_id.startswith("EXACT_") else case["input"]["source"]
            settings = (
                ("default", 5, 50, []),
                ("relaxed", 3, 20, []),
                ("near_miss", 3, 20, ["--ignore-identifiers", "--max-gap-lines", "2", "--similarity", "0.7"]),
            )
            for setting, min_lines, min_tokens, extra in settings:
                run_root = OUTPUT_ROOT / setting / case_id
                input_root = run_root / "input"
                input_root.mkdir(parents=True, exist_ok=True)
                (input_root / f"reference{extension}").write_text(reference, encoding="utf-8")
                (input_root / f"candidate{extension}").write_text(candidate_source, encoding="utf-8")
                report_root = run_root / "report"
                command = [
                    str(args.jscpd), "--min-lines", str(min_lines), "--min-tokens", str(min_tokens),
                    "--reporters", "json", "--output", str(report_root), "--format", language,
                    "--mode", "weak",
                    "--silent", *extra, str(input_root),
                ]
                completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
                if completed.returncode:
                    raise RuntimeError(f"jscpd failed for {case_id}/{setting}: {completed.stderr}")
                report = json.loads((report_root / "jscpd-report.json").read_text(encoding="utf-8"))
                cross_file = [
                    clone for clone in report.get("duplicates", [])
                    if {Path(clone["firstFile"]["name"]).name,
                        Path(clone["secondFile"]["name"]).name}
                    == {f"reference{extension}", f"candidate{extension}"}
                ]
                row = {
                    "case_id": case_id,
                    "origin_id": case["origin_id"],
                    "language": language,
                    "expected_status": "exact_copy_control" if case_id.startswith("EXACT_") else truths[case_id]["expected_status"],
                    "setting": setting,
                    "min_lines": min_lines,
                    "min_tokens": min_tokens,
                    "cross_file_clones": len(cross_file),
                    "clone_kinds": sorted({clone.get("kind", "unknown") for clone in cross_file}),
                    "longest_clone_lines": max((clone["lines"] for clone in cross_file), default=0),
                    "longest_clone_tokens": max((clone["tokens"] for clone in cross_file), default=0),
                }
                print(json.dumps(row), flush=True)
                output.append(row)
    (OUTPUT_ROOT / "summary.json").write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
