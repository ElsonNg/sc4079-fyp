"""Run only block+function; reuse completed controls without rescanning them."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
from pathlib import Path
from unittest.mock import patch

from eval.ablation import run_region_types as runner
from eval.ablation.common import digest, file_hash, unseal, write_json

ARM = "block_function"
REGIONS = ("block", "function")
REFERENCES = ("all_types", "no_changed")
DEFAULT_OUTPUT = runner.ROOT / "eval/frozen/active-block-function-gpu-v1"


def load_reference(directory, study, records):
    """Verify immutable controls and cache their first-repeat quality rows."""
    directory = directory.resolve()
    lock_path = directory / "study-lock.json"
    reference = unseal(json.loads(lock_path.read_text(encoding="utf-8")))
    runner.require(reference["schema"] == "region_type_ablation_gpu_v1"
                   and reference["smoke_limit"] is None, "Expected the completed full region study")
    for key in ("parent_manifest", "inputs", "model", "dependencies", "detector", "execution", "seed"):
        runner.require(reference[key] == study[key], "Reference setting/input mismatch: " + key)
    runner.require(all(study["code"].get(name) == sha for name, sha in reference["code"].items()),
                   "Detector or original experiment code changed since the completed controls")
    runner.require(set(study["candidate_ids"]) <= set(reference["candidate_ids"]), "New candidates absent from controls")
    runner.require(all(reference["hash_routes"][cid] == route for cid, route in study["hash_routes"].items()),
                   "Hash routes differ from completed controls")
    summary_path = directory / "combined/summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    runner.require(summary["study"] == digest(reference), "Reference summary belongs to another study")
    runtime_path = directory / "runtime.json"
    runtime = unseal(json.loads(runtime_path.read_text(encoding="utf-8")))
    cache, checkpoint_hashes = {}, {}
    for arm in REFERENCES:
        expected_types = list(runner.TYPES) if arm == "all_types" else ["block", "context", "function"]
        runner.require(reference["arms"][arm] == expected_types, "Unexpected control region types")
        for repeat in range(1, reference["repetitions"]+1):
            marker = unseal(json.loads((runner.pass_dir(directory, arm, repeat)/"complete.json").read_text(encoding="utf-8")))
            runner.require(marker["study"] == digest(reference) and marker["arm"] == arm
                           and marker["repeat"] == repeat
                           and marker["candidate_ids"] == sorted(reference["candidate_ids"]),
                           "Reference control is incomplete or mismatched")
        cache[arm] = {}
        for record in records:
            path = runner.checkpoint_path(directory, arm, 1, record["candidate_id"])
            value = json.loads(path.read_text(encoding="utf-8"))
            body = unseal(value)
            runner.require(body["identity"] == digest([digest(reference), arm, 1, record]),
                           "Reference checkpoint candidate/study mismatch")
            row = body["row"]
            runner.require(row["arm"] == arm and row["repetition"] == 1
                           and row["candidate_id"] == record["candidate_id"], "Reference row mismatch")
            cache[arm][record["candidate_id"]] = {k: v for k, v in row.items() if k != "result"}
            checkpoint_hashes[arm + ":" + record["candidate_id"]] = value["content_sha256"]
    provenance = {"path": str(directory), "study_sha256": digest(reference),
                  "lock_file_sha256": file_hash(lock_path), "summary_file_sha256": file_hash(summary_path),
                  "runtime": runtime, "runtime_file_sha256": file_hash(runtime_path),
                  "selected_checkpoint_set_sha256": digest(checkpoint_hashes),
                  "roles": {"all_types": "Effect of removing both changed and context",
                            "no_changed": "Effect of removing context after changed is already excluded"}}
    return provenance, cache, summary


def gpu_identity():
    import torch
    properties = torch.cuda.get_device_properties(0)
    return {"gpu": properties.name, "capability": [properties.major, properties.minor],
            "torch_cuda": torch.version.cuda, "cudnn": torch.backends.cudnn.version()}


def write_comparisons(output, study, records, cache, reference_summary, read_checkpoint):
    summary_path = output / "combined/summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["reference_study"] = study["reference_study"]
    comparisons, changes = [], []
    if runner.complete_pass(output, study, ARM, 1, records):
        for record in records:
            row = read_checkpoint(output, study, ARM, 1, record)
            for control in REFERENCES:
                baseline = cache[control][record["candidate_id"]]
                diff = {k: {"control": baseline[k], "arm": row[k]} for k in runner.QUALITY
                        if baseline[k] != row[k] and k not in {"candidate_region_count", "candidate_type_counts"}}
                if diff:
                    changes.append(dict(reference_arm=control, arm=ARM, candidate_id=record["candidate_id"],
                                        tier=row["tier"], split=row["split"], hash_path=row["hash_path"], changes=diff))
    if study["smoke_limit"] is None:
        for current in summary["summaries"]:
            for baseline in reference_summary["summaries"]:
                if (baseline["arm"] in REFERENCES
                    and all(current[k] == baseline[k] for k in ("tier", "split", "route"))
                    and current["metrics"]["cases"] == baseline["metrics"]["cases"]):
                    comparisons.append(dict(reference_arm=baseline["arm"], tier=current["tier"],
                                            split=current["split"], route=current["route"],
                                            reference=baseline, block_function=current))
    summary["comparisons"] = comparisons
    write_json(summary_path, summary)
    write_json(output / "combined/reference-case-changes.json",
               {"study": digest(study), "reference_study": study["reference_study"], "changes": changes})

    def cell(rate):
        return f"{rate['count']}/{rate['denominator']} ({100*rate['rate']:.2f}%)" if rate["rate"] is not None else "N/A"

    path = output / "combined/tables.md"
    content = path.read_text(encoding="utf-8").replace("# Region-type ablation", "# Block + function only")
    content += ("\n## Comparison with completed settings\n\n"
                "Only `block_function` is scanned in this run. The two controls are reused from the completed study. "
                "Paired candidate changes against each control are in `reference-case-changes.json`. "
                "Reference timing and new timing come from separate sessions; compare timing descriptively.\n\n")
    for split in ("all", "tuning", "evaluation"):
        for route in ("all", "non_hash"):
            scoped = [c for c in comparisons if (c["tier"], c["split"], c["route"]) == ("tier2", split, route)]
            if not scoped:
                continue
            rows = [c["reference"] for c in scoped] + [scoped[0]["block_function"]]
            content += f"### Tier 2 / {split} / {route}\n\n"
            content += "| Setting | Correct origin | Patched false alerts | Reviews | Median detector seconds |\n|---|---|---|---|---:|\n"
            for value in rows:
                m = value["metrics"]
                content += f"| {value['arm']} | {cell(m['correct_origin_recall'])} | {cell(m['patched_false_alert_rate'])} | {cell(m['review_rate'])} | {value['median_detector_seconds']:.2f} |\n"
            content += "\n"
    if study["smoke_limit"] is not None:
        content += "Pilot scope: full-cohort control tables are omitted because their denominators differ. Paired changes use the same selected pilot cases.\n"
    path.write_text(content, encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--reference-output", type=Path, default=runner.DEFAULT_OUTPUT)
    options, remaining = parser.parse_known_args(argv)
    original_prepare, original_collect = runner.prepare, runner.collect
    original_reader, original_files = runner.read_checkpoint, runner.code_files
    original_loader = runner.load_detector
    references = {}

    def files():
        return [*original_files(), Path(__file__), runner.ROOT / "scripts/run_block_function_ablation.ps1"]

    def prepare(args):
        study, records, resources = original_prepare(args)
        provenance, cache, summary = load_reference(options.reference_output, study, records)
        study.update(schema="block_function_followup_gpu_v1", reference_study=provenance,
                     question="Remove changed and context; retain block and function")
        references.update(cache=cache, summary=summary, runtime=provenance["runtime"])
        return study, records, resources

    def read(output, study, arm, repeat, record):
        # The existing execution/collection helpers request their all_types
        # control here. Supply the verified saved control; never scan it again.
        if arm == "all_types":
            runner.require(repeat == 1, "Only reference quality repetition 1 is used")
            return references["cache"][arm][record["candidate_id"]]
        return original_reader(output, study, arm, repeat, record)

    def collect(output, study, records):
        original_collect(output, study, records)
        write_comparisons(output, study, records, references["cache"], references["summary"], original_reader)

    def load_detector(study, resources):
        runner.require(gpu_identity() == references["runtime"], "GPU/runtime differs from completed controls")
        return original_loader(study, resources)

    with ExitStack() as stack:
        for name, value in (("ARMS", {ARM: REGIONS}), ("DEFAULT_OUTPUT", DEFAULT_OUTPUT),
                            ("code_files", files), ("prepare", prepare),
                            ("read_checkpoint", read), ("collect", collect), ("load_detector", load_detector)):
            stack.enter_context(patch.object(runner, name, value))
        return runner.main(remaining)


if __name__ == "__main__":
    raise SystemExit(main())
