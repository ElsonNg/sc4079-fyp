"""Contrast jscpd and ProvTrail retrieval on one matched 30-origin source pool."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pipeline.controller.hashing import lookup
from pipeline.controller.region_detection import RegionDetectorConfig, build_region_detector
from pipeline.controller.region_extraction import enumerate_candidate_regions, source_is_supported
from pipeline.controller.region_retrieval import aggregate_region_hits, query_region_batch
from eval.comparison_benchmark.run_jscpd_clone_30 import OUTPUT, SETTINGS, samples
from eval.tier2.validate_llm_transformed_subset import _fixture_entries


def _identity(value) -> tuple:
    def get(item, name, default=None):
        return item.get(name, default) if isinstance(item, dict) else getattr(item, name, default)

    origin = get(value, "origin", value)
    advisory = get(value, "advisory", value)
    return (
        get(advisory, "ghsa_id"), get(origin, "fix_commit_sha"),
        get(origin, "file_path"), get(origin, "function_name"),
    )


def run_jscpd_pool(
    jscpd: Path, chosen: list[dict], output_root: Path = OUTPUT,
    settings=SETTINGS,
) -> tuple[list[dict], dict[str, float]]:
    input_root = output_root / "pool" / "input"
    input_root.mkdir(parents=True, exist_ok=True)
    owners: dict[str, tuple[str, str]] = {}
    for sample in chosen:
        ext = ".js" if sample["language"] == "javascript" else ".ts"
        name = sample["sample_id"]
        record = sample["fixture_record"]
        for side, source in (
            ("vulnerable", sample["reference"]),
            ("patched", record["patched_function"]),
            ("candidate", sample["candidate"]),
        ):
            basename = f"{side}__{name}{ext}"
            (input_root / basename).write_text(source, encoding="utf-8")
            owners[basename] = (name, side)
    rows = []
    timings = {}
    for setting, min_lines, min_tokens, extra in settings:
        report_root = output_root / "pool" / setting / "report"
        command = [
            str(jscpd), "--min-lines", str(min_lines), "--min-tokens", str(min_tokens),
            "--reporters", "json", "--output", str(report_root),
            "--format", "javascript,typescript", "--mode", "weak", "--silent",
            *extra, str(input_root),
        ]
        print(f"Running pooled jscpd {setting}...", flush=True)
        started = time.perf_counter()
        completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
        timings[setting] = round(time.perf_counter() - started, 3)
        if completed.returncode:
            raise RuntimeError(f"pooled jscpd {setting} failed: {completed.stderr}")
        report = json.loads((report_root / "jscpd-report.json").read_text(encoding="utf-8"))
        candidate_matches: dict[str, set[tuple[str, str]]] = {sample["sample_id"]: set() for sample in chosen}
        for item in report.get("duplicates", []):
            a = owners.get(Path(item["firstFile"]["name"]).name)
            b = owners.get(Path(item["secondFile"]["name"]).name)
            if a is None or b is None:
                continue
            if a[1] == "candidate" and b[1] in {"vulnerable", "patched"}:
                candidate_matches[a[0]].add(b)
            if b[1] == "candidate" and a[1] in {"vulnerable", "patched"}:
                candidate_matches[b[0]].add(a)
        for sample in chosen:
            found = candidate_matches[sample["sample_id"]]
            rows.append({
                "sample_id": sample["sample_id"], "clone_type": sample["clone_type"],
                "setting": setting,
                "correct_origin": any(name == sample["sample_id"] for name, _ in found),
                "correct_vulnerable_source": (sample["sample_id"], "vulnerable") in found,
                "correct_patched_source": (sample["sample_id"], "patched") in found,
                "any_reference": bool(found),
                "wrong_origin_count": len({name for name, _ in found if name != sample["sample_id"]}),
            })
    return rows, timings


def run_provtrail(chosen: list[dict]) -> tuple[list[dict], dict[str, float]]:
    entries = _fixture_entries([sample["fixture_record"] for sample in chosen])
    if len(entries) != len(chosen):
        raise ValueError("matched pool does not contain distinct corpus entries")
    config = RegionDetectorConfig()
    print(f"Building ProvTrail's matched {len(chosen)}-origin region index...", flush=True)
    index_started = time.perf_counter()
    detector = build_region_detector(entries, config=config, save_index_artifact=False)
    index_seconds = time.perf_counter() - index_started
    print(f"Indexed {len(detector.pairs)} region pairs", flush=True)
    query_started = time.perf_counter()
    prepared = []
    flattened = []
    for sample in chosen:
        ext = ".js" if sample["language"] == "javascript" else ".ts"
        filename = f"candidate{ext}"
        source = sample["candidate"]
        if not source_is_supported(source, filename=filename):
            prepared.append((sample, [], [], "unsupported_syntax"))
            continue
        hashes = [match for match in lookup(source, detector.hash_index, filename=filename)
                  if match.origin.source_language == sample["language"]]
        if hashes:
            prepared.append((sample, hashes, [], None))
            continue
        regions = enumerate_candidate_regions(
            source, candidate_id=sample["sample_id"], max_regions=config.max_candidate_regions,
            filename=filename,
        )
        start = len(flattened)
        flattened.extend(regions)
        prepared.append((sample, [], (start, len(flattened)), None))
    print(f"Encoding/querying {len(flattened)} candidate regions...", flush=True)
    batches = query_region_batch(
        flattened, detector.region_index,
        top_k=config.retrieval_top_k, threshold=config.retrieval_threshold,
    )
    rows = []
    for sample, hashes, offsets, error in prepared:
        expected = _identity(sample["origin"])
        correct_hash_types = sorted({
            match.match_type for match in hashes if _identity(match) == expected
        })
        if hashes:
            raw_rank = 1 if correct_hash_types else None
            shortlist_hit = bool(correct_hash_types)
            any_reference = True
            retrieval_path = "hash"
        elif error:
            raw_rank = None
            shortlist_hit = False
            any_reference = False
            retrieval_path = error
        else:
            start, end = offsets
            matches = [match for batch in batches[start:end] for match in batch
                       if match.origin.source_language == sample["language"]]
            grouped = aggregate_region_hits(matches)
            raw_rank = next(
                (rank for rank, (pair_id, _) in enumerate(grouped, 1)
                 if _identity(detector.pairs[pair_id]) == expected), None
            )
            shortlist_hit = raw_rank is not None and raw_rank <= config.max_verification_candidates
            any_reference = bool(grouped[:config.max_verification_candidates])
            retrieval_path = "region"
        rows.append({
            "sample_id": sample["sample_id"], "clone_type": sample["clone_type"],
            "retrieval_path": retrieval_path, "correct_hash_types": correct_hash_types,
            "correct_raw_rank": raw_rank, "correct_shortlist": shortlist_hit,
            "any_reference": any_reference,
        })
    query_seconds = time.perf_counter() - query_started
    return rows, {
        "index_seconds": round(index_seconds, 3),
        "candidate_query_seconds": round(query_seconds, 3),
        "candidate_count": len(chosen),
        "encoded_candidate_regions": len(flattened),
        "indexed_region_pairs": len(detector.pairs),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--jscpd", type=Path, required=True)
    args = parser.parse_args()
    chosen = samples()
    jscpd_rows, jscpd_timings = run_jscpd_pool(args.jscpd, chosen)
    provtrail_rows, provtrail_timings = run_provtrail(chosen)
    output = {
        "schema": "clone_retrieval_30_contrast_v1",
        "sample_count": len(chosen),
        "reference_pool_origins": len(chosen),
        "jscpd_version": "5.3.0",
        "jscpd": jscpd_rows,
        "provtrail": provtrail_rows,
        "timings_seconds": {"jscpd_scan": jscpd_timings, "provtrail": provtrail_timings},
    }
    path = OUTPUT / "contrast.json"
    path.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    for setting, *_ in SETTINGS:
        print(setting, dict(Counter(
            row["clone_type"] for row in jscpd_rows
            if row["setting"] == setting and row["correct_origin"]
        )))
    print("provtrail", dict(Counter(
        row["clone_type"] for row in provtrail_rows if row["correct_shortlist"]
    )))
    print("timings_seconds", json.dumps(output["timings_seconds"]))
    print(f"Saved {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
