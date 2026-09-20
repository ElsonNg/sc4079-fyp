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
import argparse
from datetime import datetime
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from dotenv import load_dotenv

from provtrail.corpus.controller.build import build_corpus, print_attrition_report
from provtrail.corpus.integrations.sqlite_store import DEFAULT_DB_PATH, get_connection, load_entries, save_entries


def _parse_package_file(path: Path) -> tuple[str, ...]:
    """Read package names from a line- or comma-separated allowlist file."""
    packages: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0]
        for item in line.split(","):
            package = item.strip().strip("'\"")
            if package:
                packages.add(package)
    return tuple(sorted(packages))


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Rebuild the persisted native JS/TS corpus.")
    parser.add_argument(
        "--packages-file",
        type=Path,
        help="Only rebuild advisories for packages listed in this file (one per line or comma-separated).",
    )
    parser.add_argument(
        "--package",
        dest="packages",
        action="append",
        default=[],
        help="Restrict the rebuild to one package; may be supplied more than once.",
    )
    return parser.parse_args()


def _progress(event: dict) -> None:
    """Print bounded rebuild progress without exposing source or token data."""
    phase = event.get("phase")
    stamp = datetime.now().strftime("%H:%M:%S")
    if phase == "discovery_complete":
        print(f"[{stamp}] Discovery complete: {event.get('advisories', 0)} advisories", flush=True)
    elif phase == "advisory_start":
        print(
            f"[{stamp}] Advisory {event.get('index')}/{event.get('total')}: "
            f"{event.get('ghsa_id')}", flush=True
        )
    elif phase == "package_start":
        print(
            f"[{stamp}] Processing {event.get('ghsa_id')} / "
            f"{event.get('package')}", flush=True
        )
    elif phase == "candidate_start":
        commit = str(event.get("commit") or "")[:12]
        print(
            f"[{stamp}] Fetching evidence: {event.get('package')} "
            f"{event.get('repo')}@{commit}", flush=True
        )
    elif phase == "candidate_admitted":
        print(
            f"[{stamp}] Accepted: {event.get('package')} "
            f"({event.get('pairs', 0)} function pair(s))", flush=True
        )
    elif phase == "candidate_quarantined":
        print(
            f"[{stamp}] Quarantined: {event.get('package')} "
            f"({event.get('reason')})", flush=True
        )

if __name__ == "__main__":
    load_dotenv()
    args = _parse_args()
    selected_packages = {package.strip() for package in args.packages if package.strip()}
    if args.packages_file:
        if not args.packages_file.is_file():
            raise SystemExit(f"Package allowlist not found: {args.packages_file}")
        selected_packages.update(_parse_package_file(args.packages_file))
    package_allowlist = tuple(sorted(selected_packages)) or None

    before = len(load_entries())
    print(f"Existing corpus: {before} entries", flush=True)
    if package_allowlist:
        print(
            f"Starting restricted GitHub/OSV native source rebuild for "
            f"{len(package_allowlist)} package(s)...",
            flush=True,
        )
    else:
        print("Starting GitHub/OSV advisory and native source rebuild...", flush=True)

    entries, reports = build_corpus(packages=package_allowlist, progress_callback=_progress)
    for report in reports:
        print_attrition_report(report)

    conn = get_connection(DEFAULT_DB_PATH)
    with conn:
        conn.execute("DELETE FROM corpus_entries")
    conn.close()

    save_entries(entries)
    after = len(load_entries())
    print(f"\nRebuilt corpus: {after} entries (was {before})", flush=True)
