"""Evaluation-only full-detector sweeps over an immutable, reviewed experiment."""
from __future__ import annotations

import argparse
from collections import defaultdict
import copy
import csv
import itertools
import json
from pathlib import Path
import time
from unittest.mock import patch

from eval.ablation.common import digest, read_jsonl, seal, unseal, write_json, write_jsonl
from eval.ablation.freeze import baseline, load_frozen_detector, verify_manifest
from eval.metrics import expected_retrieval_fields

ACTIVE = {"retrieval_top_k", "max_verification_candidates", "retrieval_threshold",
          "minimum_edit_side_score", "minimum_edit_margin", "minimum_structure_score", "minimum_token_score"}


def expand_sweep(spec, base=None):
    base = copy.deepcopy(base or baseline())
    configs = {digest(base): {"configuration": base, "experiments": ["baseline"]}}
    for experiment in spec["experiments"]:
        grid = experiment["grid"]
        if not grid or set(grid) - ACTIVE:
            raise ValueError("Unknown or inactive sweep controls")
        for name, values in grid.items():
            if not values or any(isinstance(v, bool) or not isinstance(v, (float, int)) for v in values):
                raise ValueError("Sweep values must be nonempty numeric lists")
            if name in {"retrieval_top_k", "max_verification_candidates"}:
                if any(not isinstance(v, int) or v < 1 for v in values):
                    raise ValueError("K and verification budget must be positive integers")
            elif any(not 0 <= v <= 1 for v in values):
                raise ValueError("Thresholds must lie in [0,1]")
        for values in itertools.product(*grid.values()):
            config = copy.deepcopy(base)
            for name, value in zip(grid, values):
                (config["verifier"] if name in config["verifier"] else config)[name] = value
            cid = digest(config)
            configs.setdefault(cid, {"configuration": config, "experiments": []})["experiments"].append(experiment["name"])
    return [dict(v, configuration_id=k) for k, v in configs.items()]


def matching_pair_ids(record, pairs):
    expected = expected_retrieval_fields(record)
    return {pid for pid, p in pairs.items() if
        (p.origin.fix_commit_sha, p.origin.file_path.replace("\\", "/"), p.origin.function_name) == expected[1:] and
        expected[0] in {a.ghsa_id for a in [p.advisory, *p.advisories]} and
        p.origin.source_language == record["source_language"]}


def measure(record, result, pairs, raw_matches, elapsed):
    pids = matching_pair_ids(record, pairs)
    if not pids:
        raise ValueError("Missing expected origin for " + record["candidate_id"])
    boundaries = {pairs[p].fix_boundary_id for p in pids}
    lineages = {pairs[p].lineage_id for p in pids}
    hash_expected = [h for h in result.hash_matches if h.fix_boundary_id in boundaries]
    auto = result.priority == "automatic_vulnerability"
    vulnerable = {s.boundary.fix_boundary_id for s in result.vulnerability_states if s.status == "vulnerable"}
    correct = record["expected_status"] == "flagged" and auto and bool(vulnerable & boundaries)
    lineage_visible = any(l.lineage_id in lineages for l in result.lineages)
    boundary_visible = any(s.boundary.fix_boundary_id in boundaries for s in result.vulnerability_states)
    ranks = [m.rank for m in raw_matches if m.pair_id in pids]
    aggregate_rank = next((i for i, a in enumerate(result.aggregates, 1) if a.pair_id in pids), None)
    return {"candidate_id": record["candidate_id"], "tier": record["tier"], "package_name": record["package_name"],
        "expected_status": record["expected_status"], "source_language": record["source_language"],
        "requested_clone_type": record.get("requested_clone_type"), "reviewed_clone_type": record.get("reviewed_clone_type"),
        "priority": result.priority, "hash_path": bool(result.hash_matches), "expected_hash_hit": bool(hash_expected),
        "expected_hash_types": sorted({h.match_type for h in hash_expected}),
        "expected_raw_retrieval_rank": min(ranks) if ranks else None,
        "expected_retrieved": bool(hash_expected or ranks), "expected_shortlisted": bool(hash_expected) or aggregate_rank is not None,
        "expected_aggregate_rank": aggregate_rank,
        "expected_lineage_visible": lineage_visible,
        "expected_visible": bool(hash_expected) or (lineage_visible and boundary_visible),
        "correct_origin_automatic": correct,
        "wrong_origin_automatic": auto and bool(vulnerable - boundaries),
        "patched_false_positive": record["expected_status"] == "cleared" and auto,
        "abstained": result.priority == "manual_review", "elapsed_seconds": elapsed,
        "result": result.model_dump(mode="json")}


def run_case(detector, record):
    from provtrail.pipeline.controller import region_detection
    original = region_detection.query_regions
    captured = []

    def query(*args, **kwargs):
        matches = original(*args, **kwargs)
        captured.extend(matches)
        return matches

    start = time.perf_counter()
    with patch.object(region_detection, "query_regions", query):
        result = detector.detect(record["candidate_source"], candidate_id=record["candidate_id"],
                                 language=record["source_language"])
    return measure(record, result, detector.pairs, captured, time.perf_counter() - start)


def rate(rows, key):
    count = sum(bool(r[key]) for r in rows)
    return {"count": count, "denominator": len(rows), "rate": count / len(rows) if rows else None}


def summarize(rows):
    positives = [r for r in rows if r["expected_status"] == "flagged"]
    negatives = [r for r in rows if r["expected_status"] == "cleared"]
    decided = [r for r in rows if not r["abstained"]]
    out = {"labelled_cases": len(rows), "positive_cases": len(positives), "patched_cases": len(negatives),
           "decided_cases": len(decided), "runtime_seconds": sum(r["elapsed_seconds"] for r in rows)}
    for key in ("expected_retrieved", "expected_shortlisted", "expected_visible", "wrong_origin_automatic", "abstained"):
        out[key] = rate(rows, key)
    out["correct_origin_automatic"] = rate(positives, "correct_origin_automatic")
    out["patched_false_positive"] = rate(negatives, "patched_false_positive")
    for path in ("hash", "non_hash"):
        subset = [r for r in rows if r["hash_path"] == (path == "hash")]
        out[path + "_retrieval"] = rate(subset, "expected_retrieved")
    # Explicitly distinguish all-labelled rates from conditional non-abstention rates.
    out["conditional_correct_origin_recall_excluding_abstentions"] = rate([r for r in positives if not r["abstained"]], "correct_origin_automatic")
    out["conditional_patched_fp_excluding_abstentions"] = rate([r for r in negatives if not r["abstained"]], "patched_false_positive")
    out["correct_origin_automatic_over_all_labelled"] = rate(rows, "correct_origin_automatic")
    out["patched_false_positive_over_all_labelled"] = rate(rows, "patched_false_positive")
    return out


def nondominated(summaries):
    """Maximise correct-origin detection; minimise FP, wrong origin, abstention, time."""
    def score(s):
        return (-s["correct_origin_automatic"]["count"], s["patched_false_positive"]["count"],
                s["wrong_origin_automatic"]["count"], s["abstained"]["count"], s["runtime_seconds"])
    return [s["configuration_id"] for s in summaries if not any(
        all(a <= b for a, b in zip(score(other), score(s))) and any(a < b for a, b in zip(score(other), score(s)))
        for other in summaries)]


def checkpoint_key(manifest, config, record):
    return digest({"manifest": manifest["content_sha256"], "configuration": config, "candidate": record})


def read_checkpoint(path, key):
    value = json.loads(path.read_text(encoding="utf-8"))
    body = unseal(value)
    if body["checkpoint_key"] != key:
        raise ValueError("Checkpoint candidate/configuration/manifest mismatch")
    return body["row"]


def smoke_select(records, detector, limit):
    from provtrail.pipeline.controller.hashing import lookup
    from eval.common import extension_for
    features = {}
    for r in records:
        matches = lookup(r["candidate_source"], detector.hash_index, filename="candidate" + extension_for(r["source_language"]))
        path = "hash" if any(m.origin.source_language == r["source_language"] for m in matches) else "non_hash"
        features[r["candidate_id"]] = {"label:" + r["expected_status"], "language:" + r["source_language"], "path:" + path, "tier:" + r["tier"]}
        if r.get("requested_clone_type"):
            features[r["candidate_id"]].add("requested:" + r["requested_clone_type"])
    required = set().union(*features.values()) if features else set()
    covered, selected = set(), []
    remaining = sorted(records, key=lambda r: r["candidate_id"])
    while remaining and len(selected) < limit:
        best = max(remaining, key=lambda r: len(features[r["candidate_id"]] - covered))
        selected.append(best)
        remaining.remove(best)
        covered.update(features[best["candidate_id"]])
    if covered != required:
        raise ValueError("Smoke limit cannot cover available strata: " + str(required - covered))
    return selected, sorted(covered)


def export(output, summaries, comparisons):
    write_json(output / "summary.json", {"summaries": summaries, "tuning_tradeoffs": comparisons,
        "notes": "Known-origin retrospective benchmark. Conditional metrics exclude manual-review abstentions. Full detection per configuration. No winner selected. Runtime includes retrieval and verification, excludes model/index setup."})
    columns = ["configuration_id", "tier", "split", "labelled_cases", "positive_cases", "patched_cases", "runtime_seconds"]
    metrics = ["expected_retrieved", "expected_visible", "correct_origin_automatic", "wrong_origin_automatic", "patched_false_positive", "abstained", "hash_retrieval", "non_hash_retrieval"]
    conditional = ["conditional_correct_origin_recall_excluding_abstentions", "conditional_patched_fp_excluding_abstentions",
                   "correct_origin_automatic_over_all_labelled", "patched_false_positive_over_all_labelled"]
    flat = []
    for s in summaries:
        row = {k: s[k] for k in columns}
        for control in sorted(ACTIVE):
            row[control] = s['configuration'].get(control, s['configuration']['verifier'].get(control))
        for metric in metrics + ["expected_shortlisted"] + conditional:
            row.update({metric + "_" + k: v for k, v in s[metric].items()})
        flat.append(row)
    with (output / "summary.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(flat[0]) if flat else columns)
        writer.writeheader()
        writer.writerows(flat)
    text = ["# Frozen ablation results", "", "Counts show numerator/denominator. Tiers are separate. No winner is selected.", "",
            "| Config | K | Budget | Edit score | Margin | Structure | Token | Retrieval |",
            "|---|---:|---:|---:|---:|---:|---:|---:|"]
    shown = set()
    for s in summaries:
        if s['configuration_id'] in shown:
            continue
        shown.add(s['configuration_id'])
        c = s['configuration']
        v = c['verifier']
        text.append(f"| {s['configuration_id'][:10]} | {c['retrieval_top_k']} | {c['max_verification_candidates']} | {v['minimum_edit_side_score']} | {v['minimum_edit_margin']} | {v['minimum_structure_score']} | {v['minimum_token_score']} | {c['retrieval_threshold']} |")
    text += ["",
            "| Config | Tier / split | Retrieved | Visible | Correct origin / vulnerable | Wrong origin / all | Patched FP / patched | Abstained / all | Hash retrieval | Non-hash retrieval | Seconds |",
            "|---|---|---|---|---|---|---|---|---|---|---|"]
    for s in summaries:
        vals = [f"{s[m]['count']}/{s[m]['denominator']}" for m in metrics]
        text.append("| " + " | ".join([s["configuration_id"][:10], s["tier"] + " / " + s["split"], *vals, f"{s['runtime_seconds']:.3f}"]) + " |")
    text += ["", "Conditional rates exclude manual-review abstentions; all-labelled rates include them.", "",
             "| Config | Tier / split | Conditional correct-origin recall | Conditional patched FP | Correct-origin detections / all labelled | Patched FP / all labelled |",
             "|---|---|---|---|---|---|"]
    for s in summaries:
        vals = [f"{s[m]['count']}/{s[m]['denominator']}" for m in conditional]
        text.append("| " + " | ".join([s["configuration_id"][:10], s["tier"] + " / " + s["split"], *vals]) + " |")
    for c in comparisons:
        text += ["", f"Tuning non-dominated configurations ({c['tier']}): " + ", ".join(x[:10] for x in c["non_dominated"]),
                 "Objectives: increase correct-origin detections; reduce patched FP, wrong attribution, abstentions, and measured runtime. Runtime is sensitive to warm-up and system load."]
        text += ["", "| Config | Correct-origin count delta | Patched FP count delta | Abstention count delta | Runtime delta (s) |",
                 "|---|---:|---:|---:|---:|"]
        for delta in c["baseline_deltas"]:
            text.append(f"| {delta['configuration_id'][:10]} | {delta['correct_origin']} | {delta['patched_fp']} | {delta['abstentions']} | {delta['runtime_seconds']:.3f} |")
    (output / "tables.md").write_text("\n".join(text) + "\n", encoding="utf-8")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--sweep", type=Path, required=True)
    p.add_argument("--split", choices=["tuning", "evaluation", "all"], required=True)
    p.add_argument("--tier", choices=["tier1", "tier2", "both"], default="tier2")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--resume", action="store_true")
    p.add_argument("--smoke-limit", type=int)
    p.add_argument("--verify-direct-baseline", action="store_true")
    args = p.parse_args()
    if args.split == "all" and not args.smoke_limit:
        p.error("all splits is reserved for smoke verification")
    if args.smoke_limit is not None and args.smoke_limit < 1:
        p.error("smoke limit must be positive")
    manifest = verify_manifest(args.manifest)
    configs = expand_sweep(json.loads(args.sweep.read_text(encoding="utf-8")), manifest["baseline"])
    assignments = json.loads(Path(manifest["artifacts"]["split"]["path"]).read_text(encoding="utf-8"))["assignments"]
    records = []
    for tier in ("tier1", "tier2") if args.tier == "both" else (args.tier,):
        records.extend(read_jsonl(manifest["artifacts"][tier]["path"]))
    records = [r for r in records if args.split == "all" or assignments[r["candidate_id"]]["split"] == args.split]
    if not records:
        raise ValueError("Empty selected cohort")
    detector = load_frozen_detector(manifest, manifest["baseline"])
    coverage = []
    if args.smoke_limit:
        records, coverage = smoke_select(records, detector, args.smoke_limit)
    lock = {"manifest": manifest["content_sha256"], "configs": configs, "split": args.split, "tier": args.tier,
            "candidate_ids": [r["candidate_id"] for r in records], "smoke_coverage": coverage,
            "verify_direct_baseline": args.verify_direct_baseline}
    lockpath = args.output / "run-lock.json"
    if lockpath.exists():
        if not args.resume or json.loads(lockpath.read_text(encoding="utf-8")) != lock:
            raise ValueError("Existing output requires --resume with identical run settings")
    elif args.output.exists() and any(args.output.iterdir()):
        raise ValueError("Nonempty output directory without run lock")
    write_json(lockpath, lock)
    rows, summaries = [], []
    for cfg in configs:
        from provtrail.pipeline.detection.config import RegionDetectorConfig, RegionVerifierConfig
        config = cfg["configuration"]
        detector.config = RegionDetectorConfig(**{k:v for k,v in config.items() if k != "verifier"}, verifier=RegionVerifierConfig(**config["verifier"]))
        current = []
        for r in records:
            key = checkpoint_key(manifest, config, r)
            path = args.output / "checkpoints" / (key + ".json")
            if path.exists() and args.resume:
                row = read_checkpoint(path, key)
            else:
                row = run_case(detector, r)
                if args.verify_direct_baseline and config == manifest["baseline"]:
                    direct = detector.detect(r["candidate_source"], candidate_id=r["candidate_id"], language=r["source_language"])
                    if direct.model_dump(mode="json") != row["result"]:
                        raise ValueError("Runner/direct baseline result mismatch")
                    row["direct_baseline_verified"] = True
                row.update(configuration_id=cfg["configuration_id"], split=args.split, checkpoint_key=key)
                write_json(path, seal({"checkpoint_key": key, "row": row}))
            current.append(row)
            print(cfg["configuration_id"][:8], r["candidate_id"], row["priority"], flush=True)
        rows.extend(current)
        for tier in sorted({r["tier"] for r in current}):
            summaries.append(dict(summarize([r for r in current if r["tier"] == tier]), configuration_id=cfg["configuration_id"], tier=tier, split=args.split, configuration=config, experiments=cfg["experiments"]))
        write_jsonl(args.output / "cases.jsonl", rows)
        comparisons = []
        if args.split == "tuning":
            for tier in sorted({s["tier"] for s in summaries}):
                subset = [s for s in summaries if s["tier"] == tier]
                base = next(s for s in subset if s["configuration"] == manifest["baseline"])
                comparisons.append({"tier": tier, "non_dominated": nondominated(subset), "baseline_deltas": [
                    {"configuration_id": s["configuration_id"],
                     "correct_origin": s["correct_origin_automatic"]["count"] - base["correct_origin_automatic"]["count"],
                     "patched_fp": s["patched_false_positive"]["count"] - base["patched_false_positive"]["count"],
                     "abstentions": s["abstained"]["count"] - base["abstained"]["count"],
                     "runtime_seconds": s["runtime_seconds"] - base["runtime_seconds"]} for s in subset]})
        export(args.output, summaries, comparisons)
    verify_manifest(args.manifest)


if __name__ == "__main__":
    main()
