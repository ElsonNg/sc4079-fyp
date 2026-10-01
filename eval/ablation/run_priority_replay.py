"""Replay an experimental reporting policy over sealed results; no GPU inference."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path

from eval.ablation.common import digest, file_hash, read_jsonl, unseal, write_json
from eval.ablation.priority_policy import POLICY, PROTECTED_REASONS, experimental_priority
from eval.ablation import run_region_types as runner
from provtrail.pipeline.detection.priority import derive_priority
from provtrail.pipeline.models.result import RegionDetectionResult


DEFAULT_SOURCES = [runner.DEFAULT_OUTPUT, runner.ROOT / "eval/frozen/active-block-function-gpu-v1"]
DEFAULT_OUTPUT = runner.ROOT / "eval/frozen/active-priority-replay-v1"


def replay_row(row, threshold):
    result = RegionDetectionResult.model_validate(row["result"])
    before = result.model_dump(mode="json")
    assert derive_priority(result.lineages, result.vulnerability_states, result.package_applicabilities) == row["priority"], "Saved priority differs from current baseline"
    priority = experimental_priority(result, threshold)
    assert result.model_dump(mode="json") == before, "Replay changed boundary evidence"
    new = dict(row, priority=priority, abstained=priority == "manual_review",
               patched_false_positive=row["expected_status"] == "cleared" and priority == "automatic_vulnerability")
    # This policy never adds or removes an automatic vulnerable finding.
    assert (priority == "automatic_vulnerability") == (row["priority"] == "automatic_vulnerability")
    assert not row["hash_path"] or priority == row["priority"], "Hash priority changed"
    protected = any(s.status == "uncertain" and not s.gates.boundary_rejected
                    and (s.support.contradictions or s.abstention_reason in PROTECTED_REASONS)
                    for s in result.vulnerability_states)
    return new, protected


def transition_counts(pairs):
    released = [(a, b) for a, b, _ in pairs if a["abstained"] and not b["abstained"]]
    return {"patched_released": sum(a["expected_status"] == "cleared" for a, _ in released),
            "vulnerable_released": sum(a["expected_status"] == "flagged" for a, _ in released),
            "new_reviews": sum(not a["abstained"] and b["abstained"] for a, b, _ in pairs),
            "protected_review_cases": sum(p and a["abstained"] for a, _, p in pairs),
            "protected_reviews_retained": sum(p and a["abstained"] and b["abstained"] for a, b, p in pairs),
            "priority_transitions": dict(Counter(a["priority"] + " -> " + b["priority"] for a, b, _ in pairs if a["priority"] != b["priority"]))}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, action="append")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    sources = [p.resolve() for p in (args.source or DEFAULT_SOURCES)]
    output = args.output.resolve()
    assert all(not output.is_relative_to(p) and not p.is_relative_to(output) for p in sources), "Output must be separate from source studies"
    assert not output.exists() or not any(output.iterdir()), "Use a fresh replay output directory"
    provenance, scopes, changes = [], [], []
    for source in sources:
        lock = source / "study-lock.json"
        study = unseal(json.loads(lock.read_text(encoding="utf-8")))
        assert study["smoke_limit"] is None, "Expected full completed study"
        assert all(file_hash(runner.ROOT / name) == sha for name, sha in study["code"].items()), "Study source changed"
        assert all(file_hash(v["path"]) == v["sha256"] for v in study["inputs"].values()), "Input changed"
        assignments = json.loads(Path(study["inputs"]["split"]["path"]).read_text(encoding="utf-8"))["assignments"]
        all_records = [dict(r, split=assignments[r["candidate_id"]]["split"])
                       for tier in ("tier1", "tier2") for r in read_jsonl(study["inputs"][tier]["path"])]
        records = [r for r in all_records if r["candidate_id"] in study["candidate_ids"]]
        assert [r["candidate_id"] for r in records] == study["candidate_ids"]
        summary_path = source / "combined/summary.json"
        saved_summary = json.loads(summary_path.read_text(encoding="utf-8"))
        assert saved_summary["study"] == digest(study)
        checkpoint_hashes = {}
        for arm in study["arms"]:
            for rep in range(1, study["repetitions"] + 1):
                marker = unseal(json.loads((runner.pass_dir(source, arm, rep) / "complete.json").read_text(encoding="utf-8")))
                assert marker["study"] == digest(study) and marker["arm"] == arm and marker["repeat"] == rep
                assert marker["candidate_ids"] == sorted(study["candidate_ids"])
            pairs = []
            for record in records:
                path = runner.checkpoint_path(source, arm, 1, record["candidate_id"])
                value = json.loads(path.read_text(encoding="utf-8")); body = unseal(value)
                assert body["identity"] == digest([digest(study), arm, 1, record])
                row = body["row"]
                assert row["candidate_id"] == record["candidate_id"] and row["arm"] == arm and row["repetition"] == 1
                assert row["expected_status"] == record["expected_status"] and row["hash_path"] == study["hash_routes"][record["candidate_id"]]
                new, protected = replay_row(row, study["detector"]["verifier"]["minimum_edit_side_score"])
                pairs.append((row, new, protected))
                checkpoint_hashes[arm + ":" + record["candidate_id"]] = value["content_sha256"]
                if row["priority"] != new["priority"]:
                    changes.append({"arm": arm, "candidate_id": row["candidate_id"], "tier": row["tier"], "split": row["split"],
                                    "expected_status": row["expected_status"], "before": row["priority"], "after": new["priority"],
                                    "hash_path": row["hash_path"], "boundaries": row["boundaries"]})
            for tier in ("combined", "tier1", "tier2"):
                for split in ("all", "tuning", "evaluation"):
                    for route in ("all", "hash", "non_hash"):
                        selected = [(a, b, p) for a, b, p in pairs
                                    if (tier == "combined" or a["tier"] == tier)
                                    and (split == "all" or a["split"] == split)
                                    and (route == "all" or a["hash_path"] == (route == "hash"))]
                        if not selected:
                            continue
                        baseline = runner.metrics([a for a, _, _ in selected])
                        saved = next(s for s in saved_summary["summaries"] if (s["arm"], s["tier"], s["split"], s["route"]) == (arm, tier, split, route))
                        assert baseline == saved["metrics"], "Recomputed baseline differs from source summary"
                        scopes.append(dict(arm=arm, tier=tier, split=split, route=route, baseline=baseline,
                                           replay=runner.metrics([b for _, b, _ in selected]), transitions=transition_counts(selected)))
            print(f"Verified/replayed {arm}: {len(pairs)} cases; {sum(a['priority'] != b['priority'] for a,b,_ in pairs)} changed", flush=True)
        provenance.append(dict(path=str(source), study=digest(study), lock_sha256=file_hash(lock), summary_sha256=file_hash(summary_path),
                               selected_checkpoints_sha256=digest(checkpoint_hashes)))
    report = {"policy": POLICY, "policy_sha256": file_hash(runner.ROOT / "eval/ablation/priority_policy.py"),
              "runner_sha256": file_hash(Path(__file__)), "sources": provenance, "scopes": scopes,
              "note": "Exploratory aggregation replay; original evidence/verdicts retained. No GPU inference or new timing. Informational does not mean globally safe."}
    write_json(output / "summary.json", report)
    write_json(output / "case-changes.json", {"policy": POLICY, "changes": changes})
    lines = ["# Experimental priority replay", "", report["note"], "",
             "Only when a verified patched boundary exists: keep hash decisions and verified vulnerable findings unchanged; preserve contradiction, contrastive-conflict and hash-ambiguity reviews. Otherwise require medium/high lineage, S/T correspondence, and an explicitly identifying edit anchor on a side scoring at least the source study's existing edit-side threshold (0.90). Weaker alternatives remain recorded without forcing review. Cases without a verified patch retain the old policy.", ""]
    for split in ("tuning", "evaluation", "all"):
        lines += [f"## Tier 2 / {split}", "", "| Regions | Correct origin (unchanged) | False alerts (unchanged) | Reviews before → after | Patched released | Vulnerable released | Protected reviews retained |", "|---|---:|---:|---:|---:|---:|---:|"]
        for s in scopes:
            if (s["tier"], s["split"], s["route"]) != ("tier2", split, "all"):
                continue
            a, b, t = s["baseline"], s["replay"], s["transitions"]
            origin, fp = b["correct_origin_recall"], b["patched_false_alert_rate"]
            lines.append(f"| {s['arm']} | {origin['count']}/{origin['denominator']} | {fp['count']}/{fp['denominator']} | {a['review_rate']['count']} → {b['review_rate']['count']} | {t['patched_released']} | {t['vulnerable_released']} | {t['protected_reviews_retained']}/{t['protected_review_cases']} |")
        lines.append("")
    lines += ["## Interpretation", "", "A vulnerable-labelled case released from review is a risk even when its saved vulnerable verdict was already inconclusive. Unchanged automatic recall does not establish safety: this policy cannot alter automatic vulnerable findings by construction. Changes were selected after inspecting these retrospective cases; independent validation is needed before adoption. Replay timing excludes inference and is not a detector speed measurement.", ""]
    (output / "tables.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"Results: {output / 'tables.md'}", flush=True)


if __name__ == "__main__":
    main()
