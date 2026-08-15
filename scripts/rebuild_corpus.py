"""Rebuilds the persisted corpus (corpus/data/corpus.db) from scratch against the live
GitHub Advisory API and OSV.dev -- runs corpus.controller.build.build_corpus() for
every configured package, prints each package's attrition report, then replaces the
stored corpus_entries table with the fresh result.

save_entries() only upserts by (ghsa_id, fix_commit_sha, file_path, function_name) --
it never deletes a row that no longer appears in a fresh build. That matters here
specifically: entries dropped by the extraction.py identical-pair fix (see
docs/corpus-extraction-bugs.md) would otherwise sit in the table forever as stale
leftovers from the old buggy build. This script clears corpus_entries before saving,
only after build_corpus() has already succeeded in memory, so a network failure midway
through the rebuild can't leave the table half-cleared.

The FAISS retrieval index (corpus/data/embeddings/) is not touched here -- it already
self-detects staleness via corpus_fingerprint and rebuilds on next use
(pipeline.controller.retrieval.build_or_load_index).

Run from the repo root:
    PYTHONPATH=. .venv/bin/python scripts/rebuild_corpus.py
"""
from dotenv import load_dotenv

from corpus.controller.build import build_corpus, print_attrition_report
from corpus.controller.store import DEFAULT_DB_PATH, get_connection, load_entries, save_entries

if __name__ == "__main__":
    load_dotenv()

    before = len(load_entries())
    print(f"Existing corpus: {before} entries")

    entries, reports = build_corpus()
    for report in reports:
        print_attrition_report(report)

    conn = get_connection(DEFAULT_DB_PATH)
    with conn:
        conn.execute("DELETE FROM corpus_entries")
    conn.close()

    save_entries(entries)
    after = len(load_entries())
    print(f"\nRebuilt corpus: {after} entries (was {before})")
