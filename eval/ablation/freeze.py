"""Freeze reviewed fixtures, reference/index/model bytes and grouped split."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import asdict
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess

from eval.ablation.common import ROOT, digest, entry_identity, file_hash, identity, read_jsonl, seal, source_key, unseal, write_json, write_jsonl
from eval.common import DEFAULT_SNAPSHOT_DB
from provtrail.corpus.integrations.sqlite_store import load_entries
from provtrail.pipeline.detection.config import RegionDetectorConfig, RegionVerifierConfig


def baseline():
    return asdict(RegionDetectorConfig(retrieval_top_k=10, max_verification_candidates=10,
        retrieval_threshold=0., verifier=RegionVerifierConfig(minimum_edit_side_score=.90,
        minimum_edit_margin=.10, minimum_structure_score=.70, minimum_token_score=.70)))


def grouped_split(records, entries, seed=4079):
    """Union advisory aliases, shared fixes and source duplicates transitively."""
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        if parent[x] != x:
            parent[x] = find(parent[x])
        return parent[x]

    def union(keys):
        keys = sorted(set(keys))
        if keys:
            roots = sorted({find(k) for k in keys})
            for root in roots[1:]:
                parent[root] = roots[0]

    origin_tokens = {}
    for e in entries:
        aliases = [e.advisory.model_dump(), *[a if isinstance(a, dict) else a.model_dump() for a in e.advisory_aliases]]
        tokens = ["advisory:" + a[k] for a in aliases for k in ("ghsa_id", "cve_id", "osv_id") if a.get(k)]
        tokens.append("fix:" + digest([e.origin.repo, e.origin.fix_commit_sha]))
        # Same source references across advisories must not straddle partitions.
        tokens += ["source:" + digest(s) for s in (e.vulnerable_function, e.patched_function)]
        tokens += ["syntax:" + source_key(s, e.origin.source_language) for s in (e.vulnerable_function, e.patched_function)]
        union(tokens)
        origin_tokens[entry_identity(e)] = tokens[0]
    for r in records:
        if identity(r) not in origin_tokens:
            raise ValueError("Missing expected reference origin: " + str(identity(r)))
        tokens = [origin_tokens[identity(r)]]
        if r.get("candidate_source"):
            tokens.append("source:" + digest(r["candidate_source"]))
            tokens.append("syntax:" + source_key(r["candidate_source"], r["source_language"]))
        union(tokens)
    groups = defaultdict(list)
    for r in records:
        groups[find(origin_tokens[identity(r)])].append(r)
    totals = Counter((r.get("tier", "tier1"), r["package_name"], r["expected_status"]) for r in records)
    tier_totals = Counter(r.get("tier", "tier1") for r in records)
    counts = Counter()
    tuning = set()

    def cost(c):
        by_tier = Counter()
        for (tier, package, label), n in c.items():
            by_tier[tier] += n
        # Sparse packages with a single indivisible advisory tend to choose zero
        # tuning cases under package-only loss. Balance each tier explicitly.
        return sum((c[k] - .30 * totals[k]) ** 2 / totals[k] for k in sorted(totals)) + 4 * sum(
            (by_tier[tier] - .30 * tier_totals[tier]) ** 2 / tier_totals[tier] for tier in sorted(tier_totals))

    ordered = sorted(groups, key=lambda k: (-len(groups[k]), digest([seed, k])))
    group_counts = {g: Counter((r.get("tier", "tier1"), r["package_name"], r["expected_status"]) for r in rows)
                    for g, rows in groups.items()}
    for group in ordered:
        add = group_counts[group]
        if cost(counts + add) < cost(counts):
            counts.update(add)
            tuning.add(group)
    # Deterministic local improvements include swaps: a large group selected by
    # the greedy seed can otherwise prevent several smaller groups fitting well.
    while True:
        current = cost(counts)
        best = None
        moves = [(g,) for g in ordered] + [(a, b) for a in ordered if a in tuning
                                           for b in ordered if b not in tuning]
        for move in moves:
            trial = counts.copy()
            for g in move:
                if g in tuning:
                    trial.subtract(group_counts[g])
                else:
                    trial.update(group_counts[g])
            score = cost(trial)
            if score < current - 1e-10 and (best is None or score < best[0] - 1e-10):
                best = (score, move, trial)
        if best is None:
            break
        _, move, counts = best
        tuning.symmetric_difference_update(move)
    assignments = {}
    group_rows = []
    for group, rows in sorted(groups.items()):
        gid = digest(sorted(r["candidate_id"] for r in rows))[:20]
        partition = "tuning" if group in tuning else "evaluation"
        for r in rows:
            if r["candidate_id"] in assignments:
                raise ValueError("Duplicate candidate ID")
            assignments[r["candidate_id"]] = {"group": gid, "split": partition}
        group_rows.append({"group": gid, "split": partition, "cases": len(rows),
                           "advisories": sorted({identity(r)[0] for r in rows})})
    return {"seed": seed, "tuning_target": .30, "assignments": assignments, "groups": group_rows,
            "balancing": "Squared package/label/tier-stratum deviation plus 4x per-tier total deviation, each normalized by its population; deterministic greedy seed with improving single-group moves and swaps. Groups never split.",
            "actual_counts": dict(Counter(a["split"] for a in assignments.values())),
            "strata": [{"tier": k[0], "package": k[1], "label": k[2], "total": n, "tuning": counts[k]} for k, n in sorted(totals.items())],
            "exposure": "Retrospective grouped split. Both tiers and reference origins have historical development/evaluation exposure; not a pristine holdout. Known-origin retrieval keeps reference origins searchable."}


def tier1_targets(labels, entries):
    by_origin = {entry_identity(e): e for e in entries}
    rows, excluded = [], []
    for i, label in enumerate(labels):
        row = dict(label, candidate_id="T1-" + digest([i, label])[:20], tier="tier1")
        e = by_origin.get(identity(row))
        source = (e.vulnerable_function if row["expected_status"] == "flagged" else e.patched_function) if e else ""
        # Do not substitute a reference function for a different release target.
        if not row.get("tier1_applicable", True) or not source or digest(source) != row.get("target_source_sha256") or row.get("source_language") != e.origin.source_language:
            excluded.append(dict(row, exclusion="release_target_not_identical_to_available_reference_source"))
            continue
        row.update(candidate_source=source, candidate_source_sha256=digest(source),
            target_provenance="Historical release target digest equals frozen reference source; target-level confirmation only, no new release fetch.")
        rows.append(row)
    return rows, excluded


def artifact(path):
    return {"path": str(Path(path).resolve()), "sha256": file_hash(path)}


def verify_manifest(path):
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    m = unseal(payload)
    for name, spec in m["artifacts"].items():
        if not Path(spec["path"]).is_file() or file_hash(spec["path"]) != spec["sha256"]:
            raise ValueError("Frozen artifact mismatch: " + name)
    for spec in m["code_files"] + m["embedding_model"]["files"]:
        if not Path(spec["path"]).is_file() or file_hash(spec["path"]) != spec["sha256"]:
            raise ValueError("Frozen code/model mismatch: " + spec["path"])
    for name, version in m["dependencies"].items():
        if importlib.metadata.version(name) != version:
            raise ValueError("Frozen dependency mismatch: " + name)
    return payload


def load_frozen_detector(manifest, config):
    from provtrail.pipeline.controller.region_extraction import extract_corpus_region_pairs
    from provtrail.pipeline.controller.region_retrieval import load_region_index
    from provtrail.pipeline.controller.region_detection import RegionDetector
    from provtrail.pipeline.controller.hashing import build_hash_index
    from provtrail.pipeline.integrations import embedding
    from sentence_transformers import SentenceTransformer
    entries = load_entries(Path(manifest["artifacts"]["reference"]["path"]))
    pairs = extract_corpus_region_pairs(entries)
    directory = Path(manifest["artifacts"]["index_metadata"]["path"]).parent
    index = load_region_index(pairs, model_id=config["model_id"], directory=directory)
    if index is None:
        raise ValueError("Frozen index fingerprint mismatch or missing index; rebuilding forbidden")
    if index.index.ntotal != len(index.indexed_pair_ids) or len(index.indexed_sides) != len(index.indexed_pair_ids):
        raise ValueError("Frozen index vector/metadata cardinality mismatch")
    expected = {tuple(x) for x in manifest["expected_origins"]}
    found = set()
    indexed_ids = set(index.indexed_pair_ids)
    for pair in pairs:
        if pair.pair_id not in indexed_ids:
            continue
        for alias in [pair.advisory, *pair.advisories]:
            found.add((alias.ghsa_id, pair.origin.fix_commit_sha, pair.origin.file_path, pair.origin.function_name))
    if expected - found:
        raise ValueError("Expected origins absent from searchable index: " + str(expected - found))
    model_id = config["model_id"]
    model_lock = digest(manifest["embedding_model"])
    cached = embedding._loaded_models.get(model_id)
    if cached is None or getattr(cached, "_provtrail_frozen_model_lock", None) != model_lock:
        model = SentenceTransformer(manifest["embedding_model"]["snapshot"], device=manifest["embedding_model"]["device"], local_files_only=True)
        model.float()
        model.max_seq_length = manifest["embedding_model"]["max_seq_length"]
        model._provtrail_frozen_model_lock = model_lock
        embedding._loaded_models[model_id] = model
    return RegionDetector(entries, index, build_hash_index(entries), RegionDetectorConfig(
        **{k: v for k, v in config.items() if k != "verifier"}, verifier=RegionVerifierConfig(**config["verifier"])))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cohort", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT_DB)
    p.add_argument("--index", type=Path, default=ROOT / "corpus/data/region_embeddings")
    p.add_argument("--tier1-labels", type=Path, default=ROOT / "eval/tier1_curated_labels.jsonl")
    args = p.parse_args()
    manifest_path = args.output / "manifest.json"
    if manifest_path.exists():
        raise ValueError("Immutable manifest already exists; use a new version directory")
    from huggingface_hub import snapshot_download
    from provtrail.pipeline.integrations.embedding import DEFAULT_MAX_SEQ_LENGTH
    entries = load_entries(args.snapshot)
    if len(entries) != 301:
        raise ValueError("Expected 301 reference entries")
    attrition = json.loads((args.cohort / "attrition.json").read_text(encoding="utf-8"))
    if attrition["reference_sha256"] != file_hash(args.snapshot):
        raise ValueError("Reference corpus changed since cohort validation")
    accepted = read_jsonl(args.cohort / "accepted.jsonl")
    validation = read_jsonl(args.cohort / "validation.jsonl")
    audit = unseal(json.loads((args.cohort / "audit-lock.json").read_text(encoding="utf-8")))
    for name, sha in audit["outputs"].items():
        if file_hash(args.cohort / name) != sha:
            raise ValueError("Adjudicated cohort mismatch: " + name)
    if audit["adjudication_code_sha256"] != file_hash(ROOT / "eval/tier2/adjudicate.py"):
        raise ValueError("Adjudication code changed since final admission")
    valid = {v["candidate_id"]: v for v in validation if v["accepted"]}
    if not accepted or any(r["candidate_id"] not in valid or valid[r["candidate_id"]]["candidate_sha256"] != digest(r["candidate_source"]) for r in accepted):
        raise ValueError("Accepted fixtures missing matching accepted validation")
    by_origin = {entry_identity(e): e for e in entries}
    for r in accepted:
        e = by_origin.get(identity(r))
        if e is None or any(r.get(side + "_source_sha256") != digest(getattr(e, side + "_function")) for side in ("vulnerable", "patched")):
            raise ValueError("Reviewed fixture/reference source mismatch")
    args.output.mkdir(parents=True, exist_ok=True)
    t1, excluded = tier1_targets(read_jsonl(args.tier1_labels), entries)
    write_jsonl(args.output / "tier1.jsonl", t1)
    write_jsonl(args.output / "tier1-excluded.jsonl", excluded)
    # Include unavailable targets in grouping so they still bridge advisory groups.
    split = grouped_split(accepted + t1 + excluded, entries)
    write_json(args.output / "split.json", split)
    paths = {"reference": args.snapshot, "tier2": args.cohort / "accepted.jsonl",
             "validation": args.cohort / "validation.jsonl", "reviews": args.cohort / "reviews.jsonl",
             "attrition": args.cohort / "attrition.json", "generation_lock": args.cohort / "generation-lock.json",
             "generation_settings": args.cohort / "generation-settings.json",
             "attempts": args.cohort / "attempts.jsonl", "tier1_labels": args.tier1_labels,
             "audit_lock": args.cohort / "audit-lock.json", "adjudication": args.cohort / "adjudication.jsonl",
             "source_adjudications": args.cohort / "source-adjudications.jsonl",
             "quarantine": args.cohort / "quarantine.jsonl", "generated": args.cohort / "generated.jsonl",
             "tier1": args.output / "tier1.jsonl", "tier1_excluded": args.output / "tier1-excluded.jsonl",
             "split": args.output / "split.json"}
    # Snapshot the mutable reference/index inputs into the experiment version.
    for name, source in (("reference", args.snapshot), ("index", args.index / "qwen3-embedding-0.6b.faiss"),
                         ("index_metadata", args.index / "qwen3-embedding-0.6b.meta.json")):
        target = args.output / "reference" / source.name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        if file_hash(source) != file_hash(target):
            raise ValueError("Reference artifact changed while copying")
        paths[name] = target
    snapshot = Path(snapshot_download("Qwen/Qwen3-Embedding-0.6B", local_files_only=True))
    model_files = [artifact(f) for f in sorted(snapshot.rglob("*")) if f.is_file()]
    code = [*sorted((ROOT / "src/provtrail").rglob("*.py")), *sorted((ROOT / "eval/ablation").glob("*.py")),
            ROOT / "eval/tier2/cohort.py", ROOT / "eval/tier2/transform.py", ROOT / "eval/tier2/generate_llm_transformed_subset.py",
            ROOT / "eval/tier2/source_review.py",
            ROOT / "eval/tier2/adjudicate.py",
            ROOT / "eval/tier2/behaviour.py", ROOT / "eval/tier2/behaviour.cjs",
            ROOT / "eval/common.py", ROOT / "eval/metrics.py", ROOT / "eval/fixtures/generate_candidate_subset.py"]
    manifest = {"schema": "provtrail-frozen-experiment-v1", "artifacts": {k: artifact(v) for k, v in paths.items()},
        "reference_entries": len(entries), "baseline": baseline(),
        "index_provenance": "Existing symmetric-v3-fp32 index retained after reference fingerprint and origin checks. Historical build metadata records model ID but not the weight revision; query model bytes and index bytes are pinned separately by this freeze.",
        "expected_origins": sorted({identity(r) for r in accepted + t1}, key=str),
        "code_files": [artifact(f) for f in code],
        "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "git_status_at_freeze": subprocess.check_output(["git", "status", "--short"], cwd=ROOT, text=True),
        "dependencies": {n: importlib.metadata.version(n) for n in ("torch", "numpy", "sentence-transformers", "transformers", "faiss-cpu", "tree-sitter", "tree-sitter-javascript", "tree-sitter-typescript", "pydantic")},
        "embedding_model": {"model_id": "qwen3-embedding-0.6b", "snapshot": str(snapshot), "revision": snapshot.name,
            "precision": "float32", "device": os.environ.get("PROVTRAIL_EMBEDDING_DEVICE", "cpu"),
            "max_seq_length": DEFAULT_MAX_SEQ_LENGTH, "files": model_files}, "exposure": split["exposure"]}
    # Fail at freeze time as well as execution time for absent expected origins/index.
    load_frozen_detector(manifest, manifest["baseline"])
    write_json(manifest_path, seal(manifest))
    verify_manifest(manifest_path)
    print(manifest_path)


if __name__ == "__main__":
    main()
