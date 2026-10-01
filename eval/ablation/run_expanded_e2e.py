"""Fresh, resumable GPU detector evaluation with the promoted expanded verifier."""
from __future__ import annotations

from contextlib import ExitStack
import json
from pathlib import Path
import random
import statistics
from unittest.mock import patch

from eval.ablation import run_region_types as runner
from eval.ablation.common import digest, seal, write_json

ARM = "block_function"
REGIONS = ("block", "function")
DEFAULT_OUTPUT = runner.ROOT / "eval/frozen/active-expanded-e2e-gpu-v1"


def selected_config(model_id):
    from provtrail.pipeline.detection.config import RegionDetectorConfig, RegionVerifierConfig
    return RegionDetectorConfig(
        model_id=model_id, retrieval_top_k=5, max_verification_candidates=10,
        max_candidate_regions=96, max_verification_regions_per_pair=3,
        retrieval_threshold=0., include_local_correspondence_fallback=False,
        include_expanded_correspondence_fallback=True,
        verifier=RegionVerifierConfig(minimum_structure_score=.70, minimum_token_score=.70,
                                     minimum_edit_side_score=.90, minimum_edit_margin=.10),
    )


def execute_pass(output, study, arm, repeat, records, detector, session, interval):
    """Run every unfinished case; later repetitions check first-pass decisions."""
    order = list(records)
    random.Random(study["seed"] + repeat).shuffle(order)
    warmup = [r for r in sorted(records, key=lambda r: len(r["candidate_source"]))
              if not study["hash_routes"][r["candidate_id"]]][:3]
    rows = []
    with runner.region_mode(detector, REGIONS):
        detector.boundary_diagnostics.clear()
        print(f"WARMUP {arm} repeat {repeat} (excluded)", flush=True)
        for record in warmup:
            detector.detect(record["candidate_source"], candidate_id=record["candidate_id"],
                            language=record["source_language"])
        runner.synchronize()
        for i, record in enumerate(order, 1):
            row = runner.read_checkpoint(output, study, arm, repeat, record)
            if row is None:
                label = f"{arm} repeat {repeat}: {i}/{len(order)} | {record['candidate_id']}"
                print("START " + label, flush=True)
                with runner.heartbeat(label, interval):
                    row = runner.run_case(detector, record, study["hash_routes"][record["candidate_id"]])
                runner.require(not (set(row["candidate_type_counts"]) - set(REGIONS)), "Excluded candidate region was used")
                runner.require(not (set(row["reference_type_counts"]) - set(REGIONS)), "Excluded reference occupied a search slot")
                if repeat > 1:
                    first = runner.read_checkpoint(output, study, arm, 1, record)
                    runner.require(first is not None and runner.signature(first) == runner.signature(row),
                                   "Decision/rank changed between repeats: " + record["candidate_id"])
                row.update(session=session, arm=arm, repetition=repeat)
                if repeat > 1:
                    row.pop("result")
                write_json(runner.checkpoint_path(output, arm, repeat, record["candidate_id"]),
                           seal({"identity": digest([digest(study), arm, repeat, record]), "row": row}))
                print(f"DONE {label} | {row['priority']} | {row['elapsed_seconds']:.3f}s", flush=True)
            rows.append(row)
    sessions = sorted({r["session"] for r in rows})
    write_json(runner.pass_dir(output, arm, repeat) / "complete.json", seal({
        "study": digest(study), "arm": arm, "repeat": repeat,
        "candidate_ids": sorted(r["candidate_id"] for r in rows),
        "sessions": sessions, "interrupted": len(sessions) > 1,
        "detector_seconds": sum(r["elapsed_seconds"] for r in rows),
        "warmup_ids": [r["candidate_id"] for r in warmup],
    }))


def collect(output, study, records):
    repeats = [n for n in range(1, study["repetitions"] + 1)
               if runner.complete_pass(output, study, ARM, n, records)]
    summaries = []
    if repeats:
        runner.require(1 in repeats, "A completed later repeat is missing repeat 1")
        first = [runner.read_checkpoint(output, study, ARM, 1, r) for r in records]
        timing = [[runner.read_checkpoint(output, study, ARM, n, r) for r in records] for n in repeats]
        for tier in ("combined", "tier1", "tier2"):
            for split in ("all", "tuning", "evaluation"):
                for route in ("all", "hash", "non_hash"):
                    def selected(r):
                        return ((tier == "combined" or r["tier"] == tier)
                                and (split == "all" or r["split"] == split)
                                and (route == "all" or r["hash_path"] == (route == "hash")))
                    rows = [r for r in first if selected(r)]
                    if not rows:
                        continue
                    times = [sum(r["elapsed_seconds"] for r in rep if selected(r)) for rep in timing]
                    summaries.append(dict(arm=ARM, tier=tier, split=split, route=route,
                        completed_repeats=repeats, complete=len(repeats) == study["repetitions"],
                        metrics=runner.metrics(rows), pass_seconds=times,
                        median_detector_seconds=statistics.median(times)))
    write_json(output / "combined/summary.json", dict(study=digest(study), summaries=summaries,
        quality_repeat=1, policy="expanded_ast_v1", detector=study["detector"],
        note="Fresh detector passes, including GPU embeddings and retrieval for non-hash cases. Frozen reference vectors are retained. Quality counted once; repetitions measure timing and decision stability. Existing retrospective split; no independent holdout claim."))

    def cell(rate):
        return f"{rate['count']}/{rate['denominator']} ({100 * rate['rate']:.2f}%)" if rate["rate"] is not None else "N/A"

    lines = ["# Expanded verifier: GPU end-to-end detector evaluation", "",
        "Block/function regions; retrieval top-K 5, verification budget 10, R96/V3; S/T 0.70, edit 0.90, margin 0.10.", "",
        "CUDA FP32; hash and contrastive scoring enabled; expanded verifier enabled; LLM off. Fresh candidate embeddings, retrieval and verification run for every unfinished non-hash case. Reference vectors are reused; old candidate results are not reused.", "",
        "Timing covers the detector pipeline, with CUDA synchronization; setup, warmup and checkpoint IO are excluded. It does not measure directory discovery, report rendering or rebuilding the reference index.", "",
        "The corpus and retrospective tuning/evaluation split remain fixed. These cases have already informed development; this is a regression and runtime evaluation.", ""]
    for tier in ("tier1", "tier2", "combined"):
        lines += [f"## {tier}", "", "| Split | Route | Repeats | Cases | Correct origin | Patched false alerts | Reviews | Median seconds |",
                  "|---|---|---|---:|---|---|---|---:|"]
        for s in summaries:
            if s["tier"] != tier or s["route"] not in {"all", "non_hash"}:
                continue
            m = s["metrics"]
            lines.append(f"| {s['split']} | {s['route']} | {len(s['completed_repeats'])}/{study['repetitions']} | {m['cases']} | {cell(m['correct_origin_recall'])} | {cell(m['patched_false_alert_rate'])} | {cell(m['review_rate'])} | {s['median_detector_seconds']:.2f} |")
        lines.append("")
    lines += ["Complete hash/non-hash metrics, retrieval ranks and timing scopes are in `summary.json`; first-pass checkpoints contain full boundary evidence.", "",
              "Partial repetitions are excluded until complete. Interrupted repetitions retain their checkpoints and are marked in their completion metadata. Smoke runs are pilot checks.", ""]
    (output / "combined/tables.md").write_text("\n".join(lines), encoding="utf-8")


def main(argv=None):
    original_prepare, original_files = runner.prepare, runner.code_files

    def files():
        return [*original_files(), Path(__file__), runner.ROOT / "scripts/run_expanded_verifier_gpu.ps1"]

    def prepare(args):
        study, records, resources = original_prepare(args)
        study.update(schema="expanded_verifier_e2e_gpu_v1", verifier_policy="expanded_ast_v1",
                     purpose="Fresh GPU validation of the promoted verifier on the fixed block/function cohort")
        return study, records, resources

    with ExitStack() as stack:
        for name, value in (("ARMS", {ARM: REGIONS}), ("DEFAULT_OUTPUT", DEFAULT_OUTPUT),
                            ("detector_config", selected_config), ("code_files", files),
                            ("prepare", prepare), ("execute_pass", execute_pass), ("collect", collect)):
            stack.enter_context(patch.object(runner, name, value))
        return runner.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
