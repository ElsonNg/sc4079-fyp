"""Replay saved hash findings under the current rule; never scan or change old outputs."""
from collections import Counter
import json
from pathlib import Path

from eval.ablation.common import digest, file_hash, unseal, write_json
from provtrail.pipeline.detection.hashing import build_hash_result
from provtrail.pipeline.models.hashing import HashMatch

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "eval/comparison_raw/hash-precedence-impact-v1/results.json"


def state_signature(state):
    return (state["status"], state.get("abstention_reason"), tuple(state.get("contradictions", [])))


def replay(result):
    matches = result.get("hash_matches", [])
    if not matches:
        return None
    new = build_hash_result([HashMatch.from_record(m) for m in matches], result.get("candidate_id")).model_dump(mode="json")
    old_states = {s["fix_boundary_id"]: s for s in result["vulnerability_states"]}
    changes = []
    for state in new["vulnerability_states"]:
        old = old_states[state["fix_boundary_id"]]
        if state_signature(old) != state_signature(state):
            changes.append(dict(boundary=state["fix_boundary_id"],
                                advisories=[a["ghsa_id"] for a in state["advisories"]],
                                before=dict(zip(("status", "reason", "contradictions"), state_signature(old))),
                                after=dict(zip(("status", "reason", "contradictions"), state_signature(state)))))
    return new, changes


def aggregate(items, checked, hashed):
    return dict(checked_findings=checked, hash_findings=hashed, changed_findings=len(items),
                priority_changed=sum(i["priority_before"] != i["priority_after"] for i in items),
                changed_boundaries=sum(len(i["boundaries"]) for i in items),
                transitions=dict(Counter(f"{i['priority_before']} -> {i['priority_after']}" for i in items)),
                changes=items)


def main():
    hashes = {}
    study = ROOT / "eval/frozen/active-component-ablation-gpu-v1"
    audit = json.loads((study / "combined/operating-point-case-audit.json").read_text(encoding="utf-8"))
    hashes[str(study / "combined/operating-point-case-audit.json")] = file_hash(study / "combined/operating-point-case-audit.json")
    changes, hashed = [], 0
    for case in audit["cases"]:
        if not case["hash_path"]:
            continue
        path = study / "runs/no_containment/repeat-01/checkpoints" / (digest(case["candidate_id"]) + ".json")
        hashes[str(path.relative_to(ROOT))] = file_hash(path)
        row = unseal(json.loads(path.read_text(encoding="utf-8")))["row"]
        new, delta = replay(row["result"])
        hashed += 1
        if delta or new["priority"] != row["priority"]:
            changes.append(dict(candidate_id=case["candidate_id"], tier=case["tier"],
                                package=case["package_name"], label=case["expected_status"], split=case["split"],
                                priority_before=row["priority"], priority_after=new["priority"], boundaries=delta))
    main_cohort = aggregate(changes, len(audit["cases"]), hashed)
    context_changes, checked, hashed = [], 0, 0
    paths = sorted((ROOT / "eval/comparison_raw/sca-copy-v1/raw").glob("provtrail-*/attempt-001/provtrail.json"))
    assert len(paths) == 40
    for path in paths:
        hashes[str(path.relative_to(ROOT))] = file_hash(path)
        saved = json.loads(path.read_text(encoding="utf-8"))
        for finding in saved["findings"]:
            checked += 1
            result = finding["result"]
            value = replay(result)
            if value is None:
                continue
            hashed += 1
            new, delta = value
            if delta or new["priority"] != result["priority"]:
                context_changes.append(dict(snapshot=path.parents[1].name, path=finding["path"],
                                            function_id=finding["function_id"], function_hash=finding["function_hash"],
                                            function_name=finding["name"], start_line=finding["start_line"],
                                            priority_before=result["priority"], priority_after=new["priority"], boundaries=delta))
    result = dict(method="Saved hash-evidence replay only; non-hash verification unchanged; no GPU/model calls",
                  code_sha256={str(p.relative_to(ROOT)): file_hash(p) for p in [
                      ROOT / "src/provtrail/pipeline/detection/hashing.py", ROOT / "src/provtrail/pipeline/models/boundary.py", Path(__file__)]},
                  main_cohort=main_cohort, copied_snapshot_functions=aggregate(context_changes, checked, hashed),
                  snapshots=len(paths), input_hashes=hashes)
    write_json(OUTPUT, result)
    for name in ("main_cohort", "copied_snapshot_functions"):
        print(name, json.dumps({k:v for k,v in result[name].items() if k != "changes"}))
        for change in result[name]["changes"][:20]: print(json.dumps(change))
    print("Impact report:", OUTPUT)


if __name__ == "__main__":
    main()
