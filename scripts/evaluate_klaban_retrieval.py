"""Measure vulnerable and patched Recall@K for imported Klaban entries."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Callable

from corpus.controller.klaban import KLABAN_ID_PREFIX
from corpus.controller.store import DEFAULT_DB_PATH, load_entries
from corpus.models.corpus import CorpusEntry
from pipeline.controller.embedding import DEFAULT_MODEL_ID
from pipeline.controller.retrieval import (
    DEFAULT_EMBEDDINGS_DIR,
    RetrievalIndex,
    is_stale,
    load_index,
    query,
)


def _identity(value) -> tuple[str, str, str, str | None]:
    return (value.ghsa_id, value.fix_commit_sha, value.file_path, value.function_name)


def evaluate_recall(
    entries: list[CorpusEntry],
    retrieval_index: RetrievalIndex,
    *,
    k: int = 10,
    query_fn: Callable = query,
    progress_callback: Callable[[dict], None] | None = None,
) -> dict:
    vulnerable_hits = 0
    patched_hits = 0
    patched_total = sum(bool(entry.patched_function.strip()) for entry in entries)
    total_queries = len(entries) + patched_total
    completed = 0
    vulnerable_completed = 0
    patched_completed = 0

    def report(phase: str) -> None:
        if progress_callback is not None:
            progress_callback(
                {
                    "phase": phase,
                    "completed": completed,
                    "total": total_queries,
                    "vulnerable_completed": vulnerable_completed,
                    "vulnerable_hits": vulnerable_hits,
                    "patched_completed": patched_completed,
                    "patched_hits": patched_hits,
                }
            )

    for entry in entries:
        expected = _identity(entry)
        vulnerable_matches = query_fn(entry.vulnerable_function, retrieval_index, k=k, threshold=0.0)
        vulnerable_hits += any(_identity(match) == expected for match in vulnerable_matches)
        vulnerable_completed += 1
        completed += 1
        report("vulnerable")
        if entry.patched_function.strip():
            patched_matches = query_fn(entry.patched_function, retrieval_index, k=k, threshold=0.0)
            patched_hits += any(_identity(match) == expected for match in patched_matches)
            patched_completed += 1
            completed += 1
            report("patched")
    return {
        "k": k,
        "vulnerable_queries": len(entries),
        "vulnerable_hits": vulnerable_hits,
        "vulnerable_recall_at_k": vulnerable_hits / len(entries) if entries else 0.0,
        "patched_queries": patched_total,
        "patched_hits": patched_hits,
        "patched_recall_at_k": patched_hits / patched_total if patched_total else 0.0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db-path", type=Path, default=DEFAULT_DB_PATH)
    parser.add_argument("--index-dir", type=Path, default=DEFAULT_EMBEDDINGS_DIR)
    parser.add_argument("--model", default=DEFAULT_MODEL_ID)
    parser.add_argument("--k", type=int, default=10)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument(
        "--progress-every",
        type=int,
        default=10,
        help="Print progress every N completed queries (default: 10; 0 disables)",
    )
    args = parser.parse_args()

    entries = [entry for entry in load_entries(args.db_path) if entry.ghsa_id.startswith(KLABAN_ID_PREFIX)]
    if args.limit is not None:
        entries = entries[: args.limit]
    index_entries = load_entries(args.db_path)
    if is_stale(args.model, index_entries, dir_path=args.index_dir):
        raise SystemExit(
            "Embedding index is missing or stale. Rebuild it first with: "
            f"PYTHONPATH=. .venv/bin/python -m cli corpus index --embed-model {args.model} "
            "--skip-region-index"
        )
    retrieval_index = load_index(args.model, dir_path=args.index_dir)
    if retrieval_index is None:
        raise SystemExit("Unable to load embedding index")
    started = time.monotonic()

    def show_progress(state: dict) -> None:
        completed = state["completed"]
        total = state["total"]
        if args.progress_every <= 0 or (completed % args.progress_every and completed != total):
            return
        elapsed = time.monotonic() - started
        rate = completed / elapsed if elapsed else 0.0
        remaining = (total - completed) / rate if rate else 0.0
        vulnerable_recall = (
            state["vulnerable_hits"] / state["vulnerable_completed"]
            if state["vulnerable_completed"] else 0.0
        )
        patched_recall = (
            state["patched_hits"] / state["patched_completed"]
            if state["patched_completed"] else 0.0
        )
        print(
            f"[{completed}/{total}] phase={state['phase']} "
            f"vulnerable={vulnerable_recall:.4f} patched={patched_recall:.4f} "
            f"elapsed={elapsed / 60:.1f}m eta={remaining / 60:.1f}m",
            file=sys.stderr,
            flush=True,
        )

    result = evaluate_recall(
        entries,
        retrieval_index,
        k=args.k,
        progress_callback=show_progress,
    )
    rendered = json.dumps(result, indent=2)
    print(rendered)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
