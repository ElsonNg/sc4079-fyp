"""Score normalized comparator findings against the blinded ground truth."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval.comparison import read_jsonl, score_findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, default=ROOT / "eval" / "comparison_cases.jsonl")
    parser.add_argument("--ground-truth", type=Path, default=ROOT / "eval" / "comparison_ground_truth.jsonl")
    parser.add_argument("--findings", type=Path, action="append")
    parser.add_argument("--output", type=Path, default=ROOT / "eval" / "comparison_summary.json")
    parser.add_argument("--arm", action="append", choices=("real_source", "detached_clone", "dependency_metadata"), dest="arms")
    args = parser.parse_args()
    cases = read_jsonl(args.cases)
    truths = read_jsonl(args.ground_truth)
    if args.arms:
        allowed = {case["case_id"] for case in cases if case["arm"] in set(args.arms)}
        cases = [case for case in cases if case["case_id"] in allowed]
        truths = [truth for truth in truths if truth["case_id"] in allowed]
    finding_paths = args.findings or [ROOT / "eval" / "comparison_normalized_findings.jsonl"]
    findings = [row for path in finding_paths for row in read_jsonl(path)]
    result = score_findings(cases, truths, findings)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
