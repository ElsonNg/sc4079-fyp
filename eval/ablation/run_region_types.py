"""Fresh, resumable CUDA region-type study using the reviewed 600+600 cohorts."""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import contextmanager
from dataclasses import asdict
import importlib.metadata
import json
import os
from pathlib import Path
import random
import statistics
import threading
import time
from unittest.mock import patch
import uuid

from eval.ablation.common import digest, file_hash, read_jsonl, seal, unseal, write_json
from eval.ablation.exact_similarity import exact_backend
from eval.ablation.region_types import ARMS, TYPES, eligible_rows, region_mode
from eval.metrics import expected_retrieval_fields

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / "eval/frozen/experiment-active-v2/manifest.json"
DEFAULT_OUTPUT = ROOT / "eval/frozen/active-region-ablation-gpu-v1"
INPUTS = ("reference", "index", "index_metadata", "tier1", "tier2", "split")
POLICY = {
    "device": "cuda:0", "precision": "float32", "tf32": False,
    "deterministic_algorithms": True, "faiss_threads": 1,
    "reference_search": "Frozen HNSW graph with an eligibility selector before top-K",
    "candidate_selection": "Eligibility before the original cap and function insertion",
    "edit_backend": "Exact Myers semi-global Levenshtein; same scores and costs",
    "hashing": True, "contrastive_edits": True, "llm": False,
    "timing": "Synchronized detector seconds; excludes setup, warmup and checkpoint IO",
}
QUALITY = (
    "priority", "hash_path", "expected_hash_types", "expected_raw_rank",
    "expected_aggregate_rank", "correct_origin_automatic", "wrong_origin_automatic",
    "patched_false_positive", "abstained", "candidate_region_count",
    "candidate_type_counts", "boundaries", "lineages",
)


def require(value, message):
    if not value:
        raise ValueError(message)


def detector_config(model_id):
    from provtrail.pipeline.detection.config import RegionDetectorConfig, RegionVerifierConfig
    return RegionDetectorConfig(
        model_id=model_id, retrieval_top_k=5, max_verification_candidates=10,
        max_candidate_regions=96, max_verification_regions_per_pair=3,
        retrieval_threshold=0., include_local_correspondence_fallback=False,
        verifier=RegionVerifierConfig(minimum_structure_score=.70, minimum_token_score=.70,
                                     minimum_edit_side_score=.90, minimum_edit_margin=.10),
    )


def code_files():
    return [*sorted((ROOT / "src/provtrail").rglob("*.py")),
            *(ROOT / p for p in (
                "eval/__init__.py", "eval/metrics.py", "eval/ablation/__init__.py",
                "eval/ablation/common.py", "eval/ablation/exact_similarity.py",
                "eval/ablation/region_types.py", "eval/ablation/run_region_types.py",
                "scripts/run_region_type_ablation.ps1"))]


def signature(row):
    return {k: row[k] for k in QUALITY}


def smoke_select(records, routes, limit):
    """Round-robin strata without using detector outcomes to pick cases."""
    groups = {}
    for row in sorted(records, key=lambda r: r["candidate_id"]):
        key = (row["tier"], row["split"], row["expected_status"], routes[row["candidate_id"]])
        groups.setdefault(key, []).append(row)
    selected = []
    while len(selected) < min(limit, len(records)):
        for group in groups.values():
            if group and len(selected) < limit:
                selected.append(group.pop(0))
    return selected


def prepare(args):
    """Reuse verified data/model bytes, and lock current code in a NEW study.

    Old code hashes and old detector defaults are provenance, not assertions
    about this new implementation. Original manifests/results are never edited.
    """
    from provtrail.corpus.integrations.sqlite_store import load_entries
    from provtrail.pipeline.controller.hashing import build_hash_index, lookup
    from provtrail.pipeline.controller.region_extraction import extract_corpus_region_pairs
    from provtrail.pipeline.controller.region_retrieval import load_region_index

    parent = unseal(json.loads(args.manifest.read_text(encoding="utf-8")))
    for name in INPUTS:
        spec = parent["artifacts"][name]
        require(Path(spec["path"]).is_file() and file_hash(spec["path"]) == spec["sha256"],
                "Frozen input mismatch: " + name)
    for spec in parent["embedding_model"]["files"]:
        require(Path(spec["path"]).is_file() and file_hash(spec["path"]) == spec["sha256"],
                "Frozen model mismatch: " + spec["path"])
    for name, version in parent["dependencies"].items():
        require(importlib.metadata.version(name) == version, "Frozen dependency changed: " + name)
    config = detector_config(parent["embedding_model"]["model_id"])
    entries = load_entries(parent["artifacts"]["reference"]["path"])
    pairs = extract_corpus_region_pairs(entries)
    region_index = load_region_index(pairs, model_id=config.model_id,
                                    directory=Path(parent["artifacts"]["index"]["path"]).parent)
    require(region_index is not None, "Reference/index fingerprint mismatch; rebuilding is forbidden")
    require(len(region_index.indexed_pair_ids) == region_index.index.ntotal
            and len(region_index.indexed_sides) == region_index.index.ntotal,
            "Expected symmetric reference vector metadata")
    require(type(region_index.index).__name__ == "IndexHNSWFlat", "Expected frozen HNSW index")
    hashes = build_hash_index(entries)
    assignments = json.loads(Path(parent["artifacts"]["split"]["path"]).read_text())["assignments"]
    records = []
    routes = {}
    for tier in ("tier1", "tier2"):
        rows = read_jsonl(parent["artifacts"][tier]["path"])
        require(len(rows) == 600, "Expected 600 reviewed cases per tier")
        if args.tier != "both" and args.tier != tier:
            continue
        for row in rows:
            cid = row["candidate_id"]
            require(cid not in routes and row["tier"] == tier, "Duplicate candidate or tier mismatch")
            require(digest(row["candidate_source"]) == row["candidate_source_sha256"],
                    "Candidate source mismatch: " + cid)
            row = dict(row, split=assignments[cid]["split"])
            require(row["split"] in {"tuning", "evaluation"}, "Unexpected split")
            if args.split != "all" and row["split"] != args.split:
                continue
            filename = {"javascript": "candidate.js", "typescript": "candidate.ts", "tsx": "candidate.tsx"}[row["source_language"]]
            routes[cid] = any(h.origin.source_language == row["source_language"]
                              for h in lookup(row["candidate_source"], hashes, filename=filename))
            records.append(row)
    require(records, "Empty selected cohort")
    if args.smoke_limit:
        records = smoke_select(records, routes, args.smoke_limit)
    routes = {r["candidate_id"]: routes[r["candidate_id"]] for r in records}
    study = {
        "schema": "region_type_ablation_gpu_v1", "parent_manifest": file_hash(args.manifest),
        "inputs": {name: parent["artifacts"][name] for name in INPUTS},
        "model": dict(parent["embedding_model"], device=POLICY["device"], precision="float32"),
        "dependencies": {**parent["dependencies"], "filelock": importlib.metadata.version("filelock")},
        "code": {str(p.relative_to(ROOT)): file_hash(p) for p in code_files()},
        "detector": asdict(config), "execution": POLICY,
        "arms": {name: list(types) for name, types in ARMS.items()},
        "searchable_vector_counts": {name: len(eligible_rows(region_index, allowed))
                                     for name, allowed in ARMS.items()},
        "repetitions": args.repetitions, "seed": 4079,
        "tier": args.tier, "split": args.split, "smoke_limit": args.smoke_limit,
        "candidate_ids": [r["candidate_id"] for r in records], "hash_routes": routes,
        "scope": "Known-origin retrospective grouped evaluation; no pristine holdout claim",
    }
    return study, records, (entries, region_index, hashes, config)


@contextmanager
def gpu_execution():
    import faiss
    import torch
    require(torch.cuda.is_available(), "CUDA unavailable; CPU fallback is forbidden")
    workspace = os.environ.get("CUBLAS_WORKSPACE_CONFIG")
    deterministic = torch.are_deterministic_algorithms_enabled()
    warn = torch.is_deterministic_algorithms_warn_only_enabled()
    targets = [torch.backends, torch.backends.cuda.matmul, torch.backends.cudnn,
               torch.backends.cudnn.conv, torch.backends.cudnn.rnn]
    precision = [target.fp32_precision for target in targets]
    benchmark = torch.backends.cudnn.benchmark
    threads = faiss.omp_get_max_threads()
    try:
        os.environ["CUBLAS_WORKSPACE_CONFIG"] = ":4096:8"
        for target in targets:
            target.fp32_precision = "ieee"
        torch.backends.cudnn.benchmark = False
        torch.use_deterministic_algorithms(True)
        faiss.omp_set_num_threads(1)
        yield
    finally:
        faiss.omp_set_num_threads(threads)
        torch.use_deterministic_algorithms(deterministic, warn_only=warn)
        torch.backends.cudnn.benchmark = benchmark
        for target, value in reversed(list(zip(targets, precision))):
            target.fp32_precision = value
        if workspace is None:
            os.environ.pop("CUBLAS_WORKSPACE_CONFIG", None)
        else:
            os.environ["CUBLAS_WORKSPACE_CONFIG"] = workspace


def load_detector(study, resources):
    import torch
    from sentence_transformers import SentenceTransformer
    from provtrail.pipeline.controller.region_detection import RegionDetector
    from provtrail.pipeline.integrations import embedding
    model = SentenceTransformer(study["model"]["snapshot"], device=POLICY["device"], local_files_only=True)
    model.float()
    model.max_seq_length = study["model"]["max_seq_length"]
    require(str(model.device) == POLICY["device"], "Embedding model did not load on CUDA")
    require(all(p.dtype == torch.float32 for p in model.parameters() if p.is_floating_point()),
            "Embedding model is not FP32")
    embedding._loaded_models[resources[3].model_id] = model
    return RegionDetector(*resources)


def synchronize():
    import torch
    torch.cuda.synchronize(POLICY["device"])


@contextmanager
def study_writer(output):
    """Prevent concurrent writers; the OS releases the lock after interruption."""
    from filelock import FileLock, Timeout
    output.parent.mkdir(parents=True, exist_ok=True)
    lock = FileLock(str(output) + ".runner.lock", timeout=0)
    try:
        lock.acquire()
    except Timeout as exc:
        raise ValueError("Another process is writing this study output") from exc
    try:
        yield
    finally:
        lock.release()


@contextmanager
def heartbeat(label, interval):
    stop = threading.Event()
    start = time.perf_counter()

    def report():
        while not stop.wait(interval):
            print(f"RUNNING {label} | {time.perf_counter()-start:.0f}s", flush=True)

    thread = threading.Thread(target=report, daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join()


def run_case(detector, record, fixed_hash):
    from provtrail.pipeline.controller import region_detection as controller
    matches, candidates = [], []
    original_query = controller.query_regions

    def query(regions, *args, **kwargs):
        candidates.extend(regions)
        result = original_query(regions, *args, **kwargs)
        matches.extend(result)
        return result

    synchronize()
    start = time.perf_counter()
    with patch.object(controller, "query_regions", query):
        result = detector.detect(record["candidate_source"], candidate_id=record["candidate_id"],
                                 language=record["source_language"])
    synchronize()
    elapsed = time.perf_counter() - start
    require(bool(result.hash_matches) == fixed_hash, "Region selection changed the hash route")
    expected = expected_retrieval_fields(record)
    pids = {pid for pid, p in detector.pairs.items()
            if (p.origin.fix_commit_sha, p.origin.file_path.replace("\\", "/"), p.origin.function_name) == expected[1:]
            and expected[0] in {a.ghsa_id for a in [p.advisory, *p.advisories]}
            and p.origin.source_language == record["source_language"]}
    require(pids, "Missing expected origin: " + record["candidate_id"])
    boundaries = {detector.pairs[pid].fix_boundary_id for pid in pids}
    vulnerable = {s.boundary.fix_boundary_id for s in result.vulnerability_states if s.status == "vulnerable"}
    expected_hash = [h for h in result.hash_matches if h.fix_boundary_id in boundaries]
    raw_ranks = [m.rank for m in matches if m.pair_id in pids]
    aggregate_rank = next((i for i, a in enumerate(result.aggregates, 1) if a.pair_id in pids), None)
    auto = result.priority == "automatic_vulnerability"
    return {
        "candidate_id": record["candidate_id"], "tier": record["tier"], "split": record["split"],
        "package_name": record["package_name"], "expected_status": record["expected_status"],
        "priority": result.priority, "hash_path": fixed_hash,
        "expected_hash_types": sorted({h.match_type for h in expected_hash}),
        "expected_raw_rank": min(raw_ranks) if raw_ranks else None,
        "expected_aggregate_rank": 1 if expected_hash else aggregate_rank,
        "correct_origin_automatic": record["expected_status"] == "flagged" and auto and bool(vulnerable & boundaries),
        "wrong_origin_automatic": auto and bool(vulnerable - boundaries),
        "patched_false_positive": record["expected_status"] == "cleared" and auto,
        "abstained": result.priority == "manual_review", "elapsed_seconds": elapsed,
        "candidate_region_count": result.candidate_region_count,
        "candidate_type_counts": dict(Counter(c.region.granularity for c in candidates)),
        "reference_type_counts": dict(Counter(m.corpus_granularity for m in matches)),
        "boundaries": sorted([[s.boundary.fix_boundary_id, s.status, s.abstention_reason]
                              for s in result.vulnerability_states]),
        "lineages": sorted([[l.lineage_id, l.confidence] for l in result.lineages]),
        "result": result.model_dump(mode="json"),
    }


def pass_dir(output, arm, repeat):
    return output / "runs" / arm / f"repeat-{repeat:02d}"


def checkpoint_path(output, arm, repeat, cid):
    return pass_dir(output, arm, repeat) / "checkpoints" / (digest(cid) + ".json")


def read_checkpoint(output, study, arm, repeat, record):
    path = checkpoint_path(output, arm, repeat, record["candidate_id"])
    if not path.exists():
        return None
    data = unseal(json.loads(path.read_text(encoding="utf-8")))
    identity = digest([digest(study), arm, repeat, record])
    require(data["identity"] == identity, "Checkpoint belongs to another study/candidate")
    require(data["row"]["candidate_id"] == record["candidate_id"], "Checkpoint candidate mismatch")
    return data["row"]


def execute_pass(output, study, arm, repeat, records, detector, session, interval):
    order = list(records)
    random.Random(study["seed"] + repeat).shuffle(order)
    allowed = ARMS[arm]
    warmup = [r for r in sorted(records, key=lambda r: len(r["candidate_source"]))
              if not study["hash_routes"][r["candidate_id"]]][:3]
    rows = []
    with region_mode(detector, allowed):
        detector.boundary_diagnostics.clear()
        print(f"WARMUP {arm} repeat {repeat} (excluded)", flush=True)
        for record in warmup:
            detector.detect(record["candidate_source"], candidate_id=record["candidate_id"], language=record["source_language"])
        synchronize()
        for i, record in enumerate(order, 1):
            row = read_checkpoint(output, study, arm, repeat, record)
            if row is None:
                label = f"{arm} repeat {repeat}: {i}/{len(order)} | {record['candidate_id']}"
                print("START " + label, flush=True)
                with heartbeat(label, interval):
                    row = run_case(detector, record, study["hash_routes"][record["candidate_id"]])
                require(not (set(row["candidate_type_counts"]) - set(allowed)), "Excluded candidate region was used")
                require(not (set(row["reference_type_counts"]) - set(allowed)), "Excluded reference occupied a search slot")
                if arm != "all_types" and row["hash_path"]:
                    control = read_checkpoint(output, study, "all_types", 1, record)
                    require(control is not None and signature(control) == signature(row), "Hash decisions changed across region arms")
                if repeat > 1:
                    first = read_checkpoint(output, study, arm, 1, record)
                    require(first is not None and signature(first) == signature(row), "Decision/rank changed between repeats: " + record["candidate_id"])
                row.update(session=session, arm=arm, repetition=repeat)
                if repeat > 1:
                    row.pop("result")
                write_json(checkpoint_path(output, arm, repeat, record["candidate_id"]),
                           seal({"identity": digest([digest(study), arm, repeat, record]), "row": row}))
                print(f"DONE {label} | {row['priority']} | {row['elapsed_seconds']:.3f}s", flush=True)
            rows.append(row)
    sessions = sorted({r["session"] for r in rows})
    write_json(pass_dir(output, arm, repeat) / "complete.json", seal({
        "study": digest(study), "arm": arm, "repeat": repeat,
        "candidate_ids": sorted(r["candidate_id"] for r in rows),
        "sessions": sessions, "interrupted": len(sessions) > 1,
        "detector_seconds": sum(r["elapsed_seconds"] for r in rows),
        "warmup_ids": [r["candidate_id"] for r in warmup],
    }))


def fraction(count, denominator):
    return {"count": count, "denominator": denominator,
            "rate": count / denominator if denominator else None}


def metrics(rows):
    positive = [r for r in rows if r["expected_status"] == "flagged"]
    patched = [r for r in rows if r["expected_status"] == "cleared"]
    auto = lambda r: r["priority"] == "automatic_vulnerability"
    ranks = [r["expected_aggregate_rank"] for r in rows]
    tp = sum(auto(r) for r in positive)
    fp = sum(auto(r) for r in patched)
    return {
        "cases": len(rows), "vulnerable_cases": len(positive), "patched_cases": len(patched),
        "automatic_recall": fraction(tp, len(positive)),
        "correct_origin_recall": fraction(sum(r["correct_origin_automatic"] for r in positive), len(positive)),
        "patched_false_alert_rate": fraction(fp, len(patched)),
        "precision": fraction(tp, tp + fp),
        "review_rate": fraction(sum(r["abstained"] for r in rows), len(rows)),
        "wrong_origin_alerts": sum(r["wrong_origin_automatic"] for r in rows),
        "raw_expected_retrieved": fraction(sum(bool(r["expected_hash_types"]) or r["expected_raw_rank"] is not None for r in rows), len(rows)),
        "aggregate_recall": {str(k): fraction(sum(rank is not None and rank <= k for rank in ranks), len(rows)) for k in (1, 5, 10)},
        "aggregate_mrr": sum(1/r for r in ranks if r is not None) / len(rows) if rows else None,
        "mean_candidate_regions": statistics.mean(r["candidate_region_count"] for r in rows) if rows else None,
        "detector_seconds": sum(r["elapsed_seconds"] for r in rows),
    }


def complete_pass(output, study, arm, repeat, records):
    path = pass_dir(output, arm, repeat) / "complete.json"
    if not path.exists():
        return False
    value = unseal(json.loads(path.read_text(encoding="utf-8")))
    require(value["study"] == digest(study) and value["arm"] == arm and value["repeat"] == repeat,
            "Completion marker belongs to another study")
    require(value["candidate_ids"] == sorted(r["candidate_id"] for r in records), "Completion marker coverage mismatch")
    for record in records:
        require(read_checkpoint(output, study, arm, repeat, record) is not None, "Completed pass is missing a checkpoint")
    return True


def collect(output, study, records):
    summaries, changes = [], []
    for arm in ARMS:
        repeats = [n for n in range(1, study["repetitions"]+1) if complete_pass(output, study, arm, n, records)]
        if not repeats:
            continue
        require(1 in repeats, "A completed later repeat is missing repeat 1")
        first = [read_checkpoint(output, study, arm, 1, r) for r in records]
        timing = [[read_checkpoint(output, study, arm, n, r) for r in records] for n in repeats]
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
                    summaries.append(dict(arm=arm, tier=tier, split=split, route=route,
                                          completed_repeats=repeats, complete=len(repeats) == study["repetitions"],
                                          metrics=metrics(rows), pass_seconds=times,
                                          median_detector_seconds=statistics.median(times)))
        if arm != "all_types":
            for record, row in zip(records, first):
                control = read_checkpoint(output, study, "all_types", 1, record)
                require(control is not None, "Missing matched control")
                diff = {k: {"control": control[k], "arm": row[k]} for k in QUALITY
                        if control[k] != row[k] and k not in {"candidate_region_count", "candidate_type_counts"}}
                if diff:
                    changes.append(dict(arm=arm, candidate_id=record["candidate_id"], tier=row["tier"],
                                        split=row["split"], route="hash" if row["hash_path"] else "non_hash", changes=diff))
    write_json(output / "combined/summary.json", {"study": digest(study), "summaries": summaries,
               "quality_repeat": 1, "note": "Quality cases counted once; repetitions measure timing/stability"})
    write_json(output / "combined/case-changes.json", {"study": digest(study), "changes": changes})

    def cell(value):
        return f"{value['count']}/{value['denominator']} ({value['rate']*100:.2f}%)" if value["rate"] is not None else "N/A"

    lines = ["# Region-type ablation", "", "K5/B10, R96/V3; hash and contrastive scoring enabled; LLM off.", "",
             "Candidate types are filtered before the cap; reference eligibility is applied during HNSW search before top-K. Full functions remain available for patch verification.", "",
             "The reference graph/vectors are retained. These timings do not measure a rebuilt smaller index or its memory savings. Quality uses repeat 1 once; timings are medians of completed repeats.", "",
             "Tuning/evaluation are the existing retrospective grouped split. Known origins remain searchable. Use the same scope and denominator when comparing arms.", ""]
    for split in ("all", "tuning", "evaluation"):
        for route in ("all", "non_hash"):
            lines += [f"## Tier 2 / {split} / {route}", "",
                      "| Arm | Repeats | Cases | Auto recall | Correct origin | Patched false alerts | Reviews | Aggregate R@5 | MRR | Median seconds |",
                      "|---|---|---:|---|---|---|---|---|---:|---:|"]
            for s in summaries:
                if (s["tier"], s["split"], s["route"]) != ("tier2", split, route):
                    continue
                m = s["metrics"]
                lines.append(f"| {s['arm']} | {len(s['completed_repeats'])}/{study['repetitions']} | {m['cases']} | {cell(m['automatic_recall'])} | {cell(m['correct_origin_recall'])} | {cell(m['patched_false_alert_rate'])} | {cell(m['review_rate'])} | {cell(m['aggregate_recall']['5'])} | {m['aggregate_mrr']:.4f} | {s['median_detector_seconds']:.2f} |")
            lines.append("")
    lines += ["Full Tier 1/combined and hash/non-hash scopes are in `summary.json`; individual changes are in `case-changes.json`.", "",
              "Partial runs are marked by their completed repetition count. Smoke outputs are pilot checks, not report findings.", ""]
    (output / "combined/tables.md").write_text("\n".join(lines), encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--count", type=int, default=6, help="Next unfinished arms to run")
    parser.add_argument("--tier", choices=("both", "tier1", "tier2"), default="both")
    parser.add_argument("--split", choices=("all", "tuning", "evaluation"), default="all")
    parser.add_argument("--smoke-limit", type=int)
    parser.add_argument("--heartbeat-seconds", type=float, default=30.)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--collect-only", action="store_true")
    args = parser.parse_args(argv)
    if not 1 <= args.count <= 6 or args.repetitions < 1 or args.heartbeat_seconds <= 0 or (args.smoke_limit is not None and args.smoke_limit < 1):
        parser.error("Use count 1..6 and positive repetitions, heartbeat and smoke limit")
    output = args.output or (DEFAULT_OUTPUT.with_name(DEFAULT_OUTPUT.name + f"-smoke-{args.smoke_limit}")
                             if args.smoke_limit else DEFAULT_OUTPUT)
    output = output.resolve()
    parent_dir = args.manifest.resolve().parent
    require(not output.is_relative_to(parent_dir), "Output must be separate from the original experiment")
    study, records, resources = prepare(args)
    lock = output / "study-lock.json"
    if lock.exists():
        require(unseal(json.loads(lock.read_text(encoding="utf-8"))) == study,
                "Study settings/source/inputs changed. Use a new output directory; do not alter the old lock.")
    else:
        require(not output.exists() or not any(output.iterdir()), "Output directory is nonempty without a study lock")
    for tier in ("tier1", "tier2"):
        subset = [r for r in records if r["tier"] == tier]
        print(f"{tier}: {len(subset)} cases; {sum(not study['hash_routes'][r['candidate_id']] for r in subset)} fixed non-hash; "
              f"splits {dict(Counter(r['split'] for r in subset))}", flush=True)
    print(f"K5/B10/R96/V3 | {args.repetitions} repeats | fresh source lock {digest(study)[:12]}", flush=True)
    print(f"Full selected study: {len(ARMS)*len(records)*args.repetitions:,} measured calls; quality cases counted once per arm.", flush=True)
    print("Eligible reference vectors: " + json.dumps(study["searchable_vector_counts"]), flush=True)
    pending = [arm for arm in ARMS if not all(complete_pass(output, study, arm, n, records)
                                             for n in range(1, args.repetitions+1))][:args.count]
    print("Next arms: " + ", ".join(pending), flush=True)
    print("Results: " + str(output / "combined/tables.md"), flush=True)
    if args.plan:
        print("Read-only plan: no model loaded, no GPU scans, no files written.")
        return 0
    if args.collect_only:
        require(lock.exists(), "No existing study to collect")
        with study_writer(output):
            collect(output, study, records)
        return 0
    if not pending:
        with study_writer(output):
            collect(output, study, records)
        return 0
    with study_writer(output), gpu_execution(), exact_backend():
        import torch
        properties = torch.cuda.get_device_properties(0)
        runtime = {"gpu": properties.name, "capability": [properties.major, properties.minor],
                   "torch_cuda": torch.version.cuda, "cudnn": torch.backends.cudnn.version()}
        runtime_path = output / "runtime.json"
        if runtime_path.exists():
            require(unseal(json.loads(runtime_path.read_text())) == runtime, "GPU/runtime changed during this study")
        if not lock.exists():
            write_json(lock, seal(study))
        write_json(runtime_path, seal(runtime))
        print("GPU confirmed: " + json.dumps(runtime), flush=True)
        detector = load_detector(study, resources)
        session = str(uuid.uuid4())
        try:
            for arm in pending:
                for repeat in range(1, args.repetitions+1):
                    if not complete_pass(output, study, arm, repeat, records):
                        execute_pass(output, study, arm, repeat, records, detector, session, args.heartbeat_seconds)
                collect(output, study, records)
        finally:
            from provtrail.pipeline.integrations import embedding
            embedding.release_models()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
