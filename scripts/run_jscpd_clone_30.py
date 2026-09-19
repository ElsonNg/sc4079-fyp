"""Reproducible 30-sample, provenance-only jscpd clone-detection pilot."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval.comparison import read_jsonl
from scripts.generate_candidate_subset import BASE_ROW_IDS, MAPPINGS, rename_identifiers, validate_candidate

DETERMINISTIC = ROOT / "eval" / "candidate_subset_30.jsonl"
TRANSFORMED = ROOT / "eval" / "llm_transformed_expanded_positive.jsonl"
COMPARISON = ROOT / "eval" / "comparison_50_cases.jsonl"
OUTPUT = ROOT / "eval" / "comparison_raw" / "jscpd_clone_30"

TYPE1_IDS = ("C01", "C03", "C05", "C06", "C07", "C08", "C09", "C14")
TYPE2_IDS = ("C10", "C11", "C12", "C13", "C15", "C16", "C19", "C22")
TYPE3_IDS = ("CMP0003", "CMP0015", "CMP0027", "CMP0039", "CMP0051", "CMP0063", "CMP0075")
TYPE4_IDS = ("CMP0009", "CMP0033", "CMP0045", "CMP0057", "CMP0069", "CMP0081", "CMP0117")

SETTINGS = (
    ("default", 5, 50, ()),
    ("renamed", 5, 50, ("--ignore-identifiers",)),
    ("near_miss", 3, 20, ("--ignore-identifiers", "--max-gap-lines", "2", "--similarity", "0.7")),
)


def samples() -> list[dict]:
    deterministic = {row["candidate_id"]: row for row in read_jsonl(DETERMINISTIC)}
    transformed = {row["candidate_source_sha256"]: row for row in read_jsonl(TRANSFORMED)}
    comparison = {row["case_id"]: row for row in read_jsonl(COMPARISON)}
    chosen: list[dict] = []
    for clone_type, ids in (("type_1", TYPE1_IDS), ("type_2", TYPE2_IDS)):
        for candidate_id in ids:
            record = deterministic[candidate_id]
            reference = record["vulnerable_function"]
            if clone_type == "type_1":
                candidate = reference
            else:
                index = int(candidate_id[1:]) - 1
                row_id = BASE_ROW_IDS[index]
                candidate = rename_identifiers(reference, MAPPINGS[row_id])
                validate_candidate(candidate, reference)
            chosen.append({
                "sample_id": f"{clone_type}-{candidate_id}", "clone_type": clone_type,
                "language": "javascript", "origin": record["corpus_entry"],
                "reference": reference, "candidate": candidate,
                "fixture_record": {**record, "source_language": "javascript"},
            })
    for clone_type, ids in (("type_3", TYPE3_IDS), ("type_4", TYPE4_IDS)):
        for candidate_id in ids:
            case = comparison[candidate_id]
            candidate = case["input"]["source"]
            digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
            record = transformed[digest]
            if record["clone_type"] != clone_type:
                raise ValueError(f"wrong clone type for {candidate_id}")
            chosen.append({
                "sample_id": f"{clone_type}-{candidate_id}", "clone_type": clone_type,
                "language": case["source_language"], "origin": record["corpus_entry"],
                "reference": record["vulnerable_function"], "candidate": candidate,
                "fixture_record": record,
            })
    if len(chosen) != 30 or Counter(row["clone_type"] for row in chosen) != {
        "type_1": 8, "type_2": 8, "type_3": 7, "type_4": 7
    }:
        raise AssertionError("30-sample selection is unbalanced")
    return chosen


def run(jscpd: Path) -> list[dict]:
    results = []
    for sample in samples():
        ext = ".js" if sample["language"] == "javascript" else ".ts"
        for name, min_lines, min_tokens, extra in SETTINGS:
            run_root = OUTPUT / name / sample["sample_id"]
            input_root = run_root / "input"
            input_root.mkdir(parents=True, exist_ok=True)
            (input_root / f"reference{ext}").write_text(sample["reference"], encoding="utf-8")
            (input_root / f"candidate{ext}").write_text(sample["candidate"], encoding="utf-8")
            report_root = run_root / "report"
            command = [
                str(jscpd), "--min-lines", str(min_lines), "--min-tokens", str(min_tokens),
                "--reporters", "json", "--output", str(report_root),
                "--format", sample["language"], "--mode", "weak", "--silent",
                *extra, str(input_root),
            ]
            completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
            if completed.returncode:
                raise RuntimeError(f"jscpd failed on {sample['sample_id']}/{name}: {completed.stderr}")
            report = json.loads((report_root / "jscpd-report.json").read_text(encoding="utf-8"))
            clones = [
                item for item in report.get("duplicates", [])
                if {Path(item["firstFile"]["name"]).name, Path(item["secondFile"]["name"]).name}
                == {f"reference{ext}", f"candidate{ext}"}
            ]
            candidate_lines = len(sample["candidate"].splitlines())
            candidate_line_fractions = [
                (side["end"] - side["start"] + 1) / candidate_lines
                for item in clones
                for side in (item["firstFile"], item["secondFile"])
                if Path(side["name"]).name == f"candidate{ext}"
            ]
            result = {
                "sample_id": sample["sample_id"], "clone_type": sample["clone_type"],
                "language": sample["language"], "origin": sample["origin"],
                "reference_lines": len(sample["reference"].splitlines()),
                "candidate_lines": candidate_lines,
                "setting": name, "detected": bool(clones), "clone_count": len(clones),
                "kinds": sorted({item.get("kind", "unknown") for item in clones}),
                "max_tokens": max((item["tokens"] for item in clones), default=0),
                "max_candidate_line_fraction": round(max(candidate_line_fractions, default=0), 3),
            }
            print(f"{sample['sample_id']} {name}: {'match' if clones else 'miss'}", flush=True)
            results.append(result)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "summary.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--jscpd", type=Path, required=True)
    args = parser.parse_args()
    rows = run(args.jscpd)
    for setting, *_ in SETTINGS:
        print(setting, {
            kind: f"{sum(row['detected'] for row in rows if row['setting'] == setting and row['clone_type'] == kind)}/"
                  f"{sum(row['setting'] == setting and row['clone_type'] == kind for row in rows)}"
            for kind in ("type_1", "type_2", "type_3", "type_4")
        })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
