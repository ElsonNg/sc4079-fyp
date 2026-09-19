"""Emit the Tier-1 self-check label manifest from corpus release metadata.

For each selected corpus entry with a complete release boundary, write two label
rows: the last-affected release (expected to flag the GHSA) and the first-fixed
release (expected not to). This step is offline and cheap — it only reads corpus
metadata. The actual download/extract/scan happens in validate_tier1_releases.py.

Run from the repo root:
    $env:PYTHONPATH="."; .venv\\Scripts\\python.exe scripts\\build_tier1_targets.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

from corpus.controller.sandbox_fetch import _NON_LIBRARY_DIR_NAMES
from corpus.controller.store import load_entries
from eval.common import DEFAULT_SNAPSHOT_DB, category_for


def _tier1_applicable(file_path: str) -> bool:
    """False when the corpus function lives in a test/example/doc path that is not
    part of the shipped library surface — such a fix cannot be recovered by scanning
    the distributed release, so it is excluded from Tier-1 recall rather than counted
    as a false negative."""
    segments = [seg.lower() for seg in file_path.replace("\\", "/").split("/")]
    if set(segments) & _NON_LIBRARY_DIR_NAMES:
        return False
    # Catch test/spec dir variants like ``spec-main`` / ``test-integration``.
    return not any(seg.startswith(("test", "spec")) for seg in segments)

DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "eval" / "tier1_release_labels.jsonl"

_REQUIRED = (
    "vulnerable_tarball", "vulnerable_artifact_sha256", "last_affected",
    "fixed_tarball", "fixed_artifact_sha256", "first_fixed",
)

# Independently refetched release source proves this corpus boundary is absent;
# another same-named Mermaid boundary is present instead. Keep regeneration from
# reintroducing the invalid vulnerable/fixed pair.
_AUDITED_ABSENT_BOUNDARIES = {
    (
        "GHSA-ghcm-xqfw-q4vr",
        "4e2d512bf5bf6f9de1a8f0a48da78dc4d09ac4f3",
        "packages/mermaid/src/mermaidAPI.ts",
        "cssImportantStyles",
    ),
}


def _boundary_identity(entry) -> tuple:
    return entry.advisory.ghsa_id, entry.origin.fix_commit_sha, entry.origin.file_path, entry.origin.function_name

def _complete(entry) -> bool:
    rb = entry.release_boundary or {}
    return all(rb.get(key) for key in _REQUIRED)


def _stratified(entries, *, total: int, per_category: int):
    by_category: dict[str, list] = defaultdict(list)
    for entry in entries:
        if _complete(entry):
            by_category[category_for(entry.advisory.package_name)].append(entry)
    selected: list = []
    for _category, bucket in sorted(by_category.items()):
        js = [e for e in bucket if e.origin.source_language == "javascript"]
        ts = [e for e in bucket if e.origin.source_language != "javascript"]
        interleaved: list = []
        for a, b in zip(js, ts):
            interleaved.extend([a, b])
        interleaved.extend(js[len(ts):] if len(js) > len(ts) else ts[len(js):])
        selected.extend(interleaved[:per_category])
    return selected[:total]


def _rows_for(entry):
    rb = entry.release_boundary
    corpus_key = {
        "ghsa_id": entry.advisory.ghsa_id,
        "fix_commit_sha": entry.origin.fix_commit_sha,
        "file_path": entry.origin.file_path,
        "function_name": entry.origin.function_name,
    }
    for kind, tarball, sha, version, status in (
        ("vulnerable", rb["vulnerable_tarball"], rb["vulnerable_artifact_sha256"], rb["last_affected"], "flagged"),
        ("fixed", rb["fixed_tarball"], rb["fixed_artifact_sha256"], rb["first_fixed"], "cleared"),
    ):
        source_commit = rb.get("last_affected_commit" if kind == "vulnerable" else "first_fixed_commit")
        yield {
            "ghsa_id": entry.advisory.ghsa_id,
            "package_name": entry.advisory.package_name,
            "category": category_for(entry.advisory.package_name),
            "source_language": entry.origin.source_language,
            "kind": kind,
            "version": version,
            "tarball_url": tarball,
            "expected_sha256": sha,
            "expected_status": status,
            "source_repo": entry.origin.repo,
            "source_commit": source_commit,
            "tier1_applicable": _tier1_applicable(entry.origin.file_path),
            "corpus_file_path": entry.origin.file_path,
            "corpus_entry": corpus_key,
            "target_source_sha256": hashlib.sha256(
                (entry.vulnerable_function if kind == "vulnerable" else entry.patched_function).encode("utf-8")
            ).hexdigest(),
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT_DB)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--entries", type=int, default=100, help="corpus entries (each -> 2 targets)")
    parser.add_argument("--per-category", type=int, default=20)
    parser.add_argument("--all", action="store_true", help="use every entry with a complete boundary")
    parser.add_argument("--pilot", action="store_true")
    args = parser.parse_args()

    entries = load_entries(args.snapshot)
    if args.pilot:
        args.entries, args.per_category = 2, 1
    # Only entries whose vulnerable function is in shipped library code are scorable
    # by a release scan; test/example-only fixes are excluded from the Tier-1 set.
    applicable = [
        e for e in entries
        if _complete(e)
        and _tier1_applicable(e.origin.file_path)
        and _boundary_identity(e) not in _AUDITED_ABSENT_BOUNDARIES
    ]
    excluded = sum(
        1 for e in entries
        if _complete(e) and (
            not _tier1_applicable(e.origin.file_path)
            or _boundary_identity(e) in _AUDITED_ABSENT_BOUNDARIES
        )
    )
    if args.all:
        selected = applicable
    else:
        selected = _stratified(applicable, total=args.entries, per_category=args.per_category)
    print(f"Excluded {excluded} entries whose fix is in test/example paths (not Tier-1 scorable)")

    rows = [row for entry in selected for row in _rows_for(entry)]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    unique_tarballs = len({row["tarball_url"] for row in rows})
    print(f"Selected {len(selected)} entries -> {len(rows)} label rows "
          f"({unique_tarballs} unique tarballs) -> {args.output}")
    print("By category:", dict(Counter(category_for(e.advisory.package_name) for e in selected)))
    print("By language:", dict(Counter(e.origin.source_language for e in selected)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
