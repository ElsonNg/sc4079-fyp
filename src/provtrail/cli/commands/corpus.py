"""Execute corpus commands and render their command-line output."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import shutil
from collections import Counter

import numpy as np
import requests

from provtrail.corpus.controller.build import build_corpus_result, print_attrition_report, probe_packages
from provtrail.corpus.controller.deduplication import deduplicate_entries
from provtrail.corpus.controller.snapshot import SnapshotIntegrityError, promote_snapshot
from provtrail.corpus.controller.klaban import KLABAN_ID_PREFIX, parse_klaban_corpus, print_klaban_report
from provtrail.corpus.integrations.sqlite_store import (
    DEFAULT_DB_PATH,
    load_entries,
    replace_entries_by_ghsa_prefix,
)
from provtrail.pipeline.integrations import embedding
from provtrail.pipeline.integrations.embedding import EMBEDDING_DEVICE_ENV
from provtrail.pipeline.controller.region_extraction import extract_corpus_region_pairs
from provtrail.pipeline.controller.region_retrieval import _region_fingerprint
from provtrail.pipeline.controller.retrieval import (
    INDEX_FORMAT_VERSION,
    _corpus_fingerprint,
    _corpus_windows,
    _match_from_entry,
    _normalized_text,
)
from provtrail.pipeline.scanning.cache import corpus_fingerprint


def _corpus_build_progress(event: dict) -> None:
    phase = event.get("phase")
    if phase == "discovery_complete":
        print(f"corpus: discovered {event['advisories']} reviewed advisory record(s)", file=sys.stderr, flush=True)
    elif phase == "advisory_start":
        print(
            f"corpus: advisory {event['index']}/{event['total']} {event['ghsa_id']}",
            file=sys.stderr, flush=True,
        )
    elif phase == "package_start":
        print(f"  package: {event['package']} ({event['ghsa_id']})", file=sys.stderr, flush=True)
    elif phase == "candidate_start":
        print(
            f"    resolve: {event['repo']}@{event['commit'][:12]}",
            file=sys.stderr, flush=True,
        )
    elif phase == "candidate_quarantined":
        print(
            f"    quarantine: {event['reason']} — {event['repo']}@{event['commit'][:12]}",
            file=sys.stderr, flush=True,
        )
    elif phase == "candidate_admitted":
        print(
            f"    admitted: {event['pairs']} function pair(s) from {event['repo']}@{event['commit'][:12]}",
            file=sys.stderr, flush=True,
        )


def build(args: argparse.Namespace) -> int:
    packages = None if args.all_packages else tuple(args.packages)
    try:
        result = build_corpus_result(packages=packages, progress_callback=_corpus_build_progress)
    except requests.RequestException as exc:
        print(f"Corpus discovery failed before candidate processing: {exc}", file=sys.stderr)
        print("No snapshot was promoted and the active corpus was not changed.", file=sys.stderr)
        return 2
    database = args.db_path or DEFAULT_DB_PATH
    if args.append and database.exists():
        existing = load_entries(database)
        result.entries, removed = deduplicate_entries(existing + result.entries)
        result.source_manifest["append_base_entries"] = len(existing)
        result.source_manifest["append_duplicates_removed"] = removed
        for report in result.reports:
            report.corpus_entries_final = len(result.entries)
            report.duplicates_removed += removed
            report.high_impact_entries = sum(entry.high_impact for entry in result.entries)
    if not result.entries:
        for report in result.reports:
            print_attrition_report(report)
        print("No corpus entries were admitted; active corpus was not changed.", file=sys.stderr)
        return 2
    try:
        snapshot = promote_snapshot(result, args.snapshots_dir)
    except SnapshotIntegrityError as exc:
        print(f"Corpus snapshot was not promoted: {exc}", file=sys.stderr)
        return 2
    database.parent.mkdir(parents=True, exist_ok=True)
    temporary = database.with_name(f".{database.name}.tmp")
    shutil.copyfile(snapshot / "corpus.db", temporary)
    temporary.replace(database)
    for report in result.reports:
        print_attrition_report(report)
    print(f"Promoted immutable snapshot {snapshot.name} with {len(result.entries)} entries")
    print(f"Active corpus database: {database}")
    return 0


def probe(args: argparse.Namespace) -> int:
    try:
        payload = probe_packages(include_withdrawn=args.include_withdrawn)
    except requests.RequestException as exc:
        print(f"Package probe failed: {exc}", file=sys.stderr)
        return 2
    all_packages = payload["packages"]
    packages = all_packages
    if args.limit is not None:
        if args.limit < 1:
            print("--limit must be greater than zero", file=sys.stderr)
            return 2
        packages = packages[: args.limit]
    payload["all_packages"] = all_packages
    payload["packages"] = packages
    payload["selected_packages"] = [item["package"] for item in packages]
    payload["selected_count"] = len(packages)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"Wrote package probe to {args.output}")
    else:
        print(f"Advisories found: {payload['advisories_found']}")
        print(f"Packages found:   {payload['package_count']}")
        print("Rank  Advisories  Package")
        for item in packages:
            print(f"{item['rank']:>4}  {item['advisories']:>10}  {item['package']}")
    return 0


def stats(args: argparse.Namespace) -> int:
    entries = load_entries(args.db_path) if args.db_path else load_entries()
    packages = Counter(entry.advisory.package_name for entry in entries)
    confirmed = sum(entry.osv_confirmed for entry in entries)
    high_impact = sum(entry.high_impact for entry in entries)
    languages = Counter(entry.origin.source_language for entry in entries)
    print(f"Corpus entries: {len(entries)}")
    print(f"OSV-confirmed:  {confirmed}")
    print(f"High impact:    {high_impact}")
    print(f"Corpus version: {corpus_fingerprint(entries)}")
    print("Packages:")
    for package, count in sorted(packages.items()):
        print(f"  {package}: {count}")
    print("Languages:")
    for language, count in sorted(languages.items()):
        print(f"  {language}: {count}")
    return 0


def index(args: argparse.Namespace) -> int:
    os.environ.setdefault("KMP_DUPLICATE_LIB_OK", "TRUE")
    if args.device:
        os.environ[EMBEDDING_DEVICE_ENV] = args.device
    entries = load_entries(args.db_path) if args.db_path else load_entries()
    print(f"Building function index for {len(entries)} corpus entries...")
    function_texts = []
    function_matches = []
    for entry in entries:
        windows = _corpus_windows(entry)
        function_texts.extend(_normalized_text(window) for window in windows)
        function_matches.extend(_match_from_entry(entry) for _ in windows)
    function_vectors = embedding.encode(
        args.model,
        function_texts,
        batch_size=args.embedding_batch_size,
        progress_callback=lambda done, total: print(f"  embedded {done}/{total} functions")
        if done == total or done % 320 == 0 else None,
    )
    args.embeddings_dir.mkdir(parents=True, exist_ok=True)
    function_index_path = args.embeddings_dir / f"{args.model}.faiss"
    function_vector_path = args.embeddings_dir / f".{args.model}.vectors.npy"
    np.save(function_vector_path, function_vectors)
    del function_vectors
    embedding.release_models()
    subprocess.run(
        [sys.executable, "-m", "provtrail.cli.faiss_builder", str(function_vector_path), str(function_index_path)],
        check=True,
    )
    function_vector_path.unlink()
    function_meta = {
        "model_id": args.model,
        "max_seq_length": embedding.DEFAULT_MAX_SEQ_LENGTH,
        "corpus_fingerprint": _corpus_fingerprint(entries),
        "index_format_version": INDEX_FORMAT_VERSION,
        "entries": [match.model_dump() for match in function_matches],
    }
    (args.embeddings_dir / f"{args.model}.meta.json").write_text(json.dumps(function_meta), encoding="utf-8")
    if args.skip_region_index:
        print(f"Indexed {len(function_matches)} windows from {len(entries)} functions with {args.model}")
        return 0

    pairs = extract_corpus_region_pairs(entries)
    print(f"Building AST-region index for {len(pairs)} vulnerable region pairs...")
    region_vectors = embedding.encode(
        args.model,
        [pair.vulnerable_region.embedding_text for pair in pairs],
        batch_size=args.embedding_batch_size,
        progress_callback=lambda done, total: print(f"  embedded {done}/{total} regions")
        if done == total or done % 320 == 0 else None,
    )
    args.region_embeddings_dir.mkdir(parents=True, exist_ok=True)
    region_index_path = args.region_embeddings_dir / f"{args.model}.faiss"
    region_vector_path = args.region_embeddings_dir / f".{args.model}.vectors.npy"
    np.save(region_vector_path, region_vectors)
    del region_vectors
    embedding.release_models()
    subprocess.run(
        [sys.executable, "-m", "provtrail.cli.faiss_builder", str(region_vector_path), str(region_index_path)],
        check=True,
    )
    region_vector_path.unlink()
    region_meta = {
        "model_id": args.model,
        "max_seq_length": embedding.DEFAULT_MAX_SEQ_LENGTH,
        "fingerprint": _region_fingerprint(pairs, args.model),
        "pairs": [pair.to_record() for pair in pairs],
    }
    (args.region_embeddings_dir / f"{args.model}.meta.json").write_text(json.dumps(region_meta), encoding="utf-8")
    print(
        f"Indexed {len(entries)} functions and {len(pairs)} AST regions with {args.model}"
    )
    return 0


def ingest_klaban(args: argparse.Namespace) -> int:
    entries, report = parse_klaban_corpus(args.path)
    if args.db_path:
        replace_entries_by_ghsa_prefix(entries, KLABAN_ID_PREFIX, args.db_path)
    else:
        replace_entries_by_ghsa_prefix(entries, KLABAN_ID_PREFIX)
    print_klaban_report(report)
    print(f"Saved {len(entries)} Klaban entries")
    if not args.skip_index:
        return index(args)
    return 0
