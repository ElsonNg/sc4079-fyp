"""Execute corpus commands and render their command-line output."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from collections import Counter

import requests

from provtrail.corpus.controller.build import build_corpus_result, print_attrition_report, probe_packages
from provtrail.corpus.controller.deduplication import deduplicate_entries
from provtrail.corpus.controller.snapshot import SnapshotIntegrityError, promote_snapshot
from provtrail.corpus.integrations.sqlite_store import (
    DEFAULT_DB_PATH,
    load_entries,
)
from provtrail.pipeline.integrations.embedding import EMBEDDING_DEVICE_ENV
from provtrail.pipeline.controller.region_extraction import extract_corpus_region_pairs
from provtrail.pipeline.controller.region_retrieval import build_region_index, save_region_index
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
    pairs = extract_corpus_region_pairs(entries)
    print(f"Building AST-region index for {len(pairs)} vulnerable region pairs...")
    region_index = build_region_index(
        pairs,
        model_id=args.model,
        embedding_batch_size=args.embedding_batch_size,
        isolate_faiss=True,
        progress_callback=lambda done, total: print(f"  embedded {done}/{total} regions")
        if done == total or done % 320 == 0 else None,
    )
    save_region_index(region_index, args.region_embeddings_dir)
    print(
        f"Indexed {len(entries)} functions and {len(pairs)} AST regions with {args.model}"
    )
    return 0
