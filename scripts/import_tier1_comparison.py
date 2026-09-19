"""Normalize canonical Tier-1 ProvTrail results for selected real-source cases."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval.comparison import read_jsonl, write_jsonl


def _key_from_result(row: dict) -> tuple:
    entry = row.get("corpus_entry", {})
    return (
        row.get("source_repo"), row.get("source_commit"),
        str(row.get("source_path") or "").replace("\\", "/"),
        entry.get("function_name") or row.get("target_function"),
        row.get("target_source_sha256"),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, default=ROOT / "eval" / "comparison_cases.jsonl")
    parser.add_argument("--ground-truth", type=Path, default=ROOT / "eval" / "comparison_ground_truth.jsonl")
    parser.add_argument("--tier1", type=Path, default=ROOT / "eval" / "tier1_production_fp32_results.json")
    parser.add_argument("--output", type=Path, default=ROOT / "eval" / "comparison_normalized_findings_pilot_tier1.jsonl")
    args = parser.parse_args()
    cases = [row for row in read_jsonl(args.cases) if row["arm"] == "real_source"]
    truths = {row["case_id"]: row for row in read_jsonl(args.ground_truth)}
    tier1 = json.loads(args.tier1.read_text(encoding="utf-8"))
    indexed = {_key_from_result(row): row for row in tier1.get("results", [])}
    records = []
    missing = []
    for case in cases:
        truth = truths[case["case_id"]]
        input_ = case["input"]
        key = (
            input_["repository"], input_["commit_sha"], input_["target_path"],
            truth.get("target_function_name"), truth.get("target_source_sha256"),
        )
        source = indexed.get(key)
        if source is None:
            missing.append(case["case_id"])
            records.append({"record_type": "execution", "tool": "provtrail", "case_id": case["case_id"],
                            "completed": False, "execution_error": "matching Tier-1 result unavailable"})
            continue
        records.append({"record_type": "execution", "tool": "provtrail", "case_id": case["case_id"],
                        "completed": True, "source_artifact": str(args.tier1)})
        priority = source.get("priority")
        if not priority:
            priority = (
                "automatic_vulnerability" if source.get("outcome") in {"true_positive", "false_positive"}
                else "manual_review" if str(source.get("outcome", "")).startswith("abstained_") else "none"
            )
        if priority != "none":
            records.append({
                "record_type": "finding", "tool": "provtrail", "case_id": case["case_id"],
                "path": input_["target_path"], "start_line": truth.get("target_start_line"),
                "end_line": truth.get("target_end_line"), "rule_id": "provtrail-lineage",
                "priority": priority, "advisory_ids": truth["advisory_aliases"],
                "cwes": truth["cwes"], "source_outcome": source.get("outcome"),
            })
    write_jsonl(args.output, records)
    print(json.dumps({"cases": len(cases), "missing": missing, "records": len(records)}, indent=2))
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
