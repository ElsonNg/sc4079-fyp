"""Materialize pinned comparison sources without installing or executing packages."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path, PurePosixPath

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from provtrail.corpus.integrations.github import fetch_source_tree
from eval.comparison import read_jsonl, write_jsonl
from provtrail.pipeline.controller.parsing import extract_function_units

WORK_ROOT = ROOT / "eval" / "comparison_workspaces"


def snapshot_key(repository: str, commit: str) -> str:
    digest = hashlib.sha256(f"{repository}@{commit}".encode("utf-8")).hexdigest()[:16]
    return f"{repository.replace('/', '__')}--{digest}"


def _safe_relative(value: str) -> Path:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe repository path: {value}")
    return Path(*path.parts)


def _write_sources(destination: Path, sources: dict[str, str]) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for relative, source in sources.items():
        target = destination / _safe_relative(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8")


def _read_materialized_sources(destination: Path) -> dict[str, str]:
    extensions = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
    return {
        str(path.relative_to(destination)).replace("\\", "/"): path.read_text(encoding="utf-8")
        for path in destination.rglob("*")
        if path.is_file() and path.suffix.lower() in extensions
    }


def _resolve_target(source: str, path: str, expected_hash: str | None,
                    function_name: str | None) -> tuple[int, int]:
    units = extract_function_units(source, filename=path)
    matches = [
        unit for unit in units
        if expected_hash and hashlib.sha256(unit.source.encode("utf-8")).hexdigest() == expected_hash
    ]
    if not matches and function_name:
        matches = [unit for unit in units if unit.name == function_name]
    if len(matches) != 1:
        raise ValueError(f"target function resolution produced {len(matches)} matches in {path}")
    # FunctionUnit follows tree-sitter's zero-based convention. Comparison
    # records use the one-based line convention used by SARIF.
    return matches[0].start_line + 1, matches[0].end_line + 1


def main() -> int:
    load_dotenv(ROOT / ".env")
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, default=ROOT / "eval" / "comparison_cases.jsonl")
    parser.add_argument("--ground-truth", type=Path, default=ROOT / "eval" / "comparison_ground_truth.jsonl")
    parser.add_argument("--max-files", type=int, default=1000)
    parser.add_argument("--max-source-bytes", type=int, default=1_000_000)
    parser.add_argument("--fetch-workers", type=int, default=8)
    args = parser.parse_args()
    cases = read_jsonl(args.cases)
    truths = {row["case_id"]: row for row in read_jsonl(args.ground_truth)}
    snapshots: dict[tuple[str, str], list[dict]] = {}
    for case in cases:
        if case["input"]["kind"] != "github_source":
            continue
        key = (case["input"]["repository"], case["input"]["commit_sha"])
        snapshots.setdefault(key, []).append(case)

    for index, ((repository, commit), snapshot_cases) in enumerate(snapshots.items(), start=1):
        owner, repo = repository.split("/", 1)
        required = {case["input"]["target_path"] for case in snapshot_cases}
        destination = WORK_ROOT / "real" / snapshot_key(repository, commit)
        print(f"[{index}/{len(snapshots)}] {repository}@{commit[:12]} ({len(required)} target(s))", flush=True)
        if destination.is_dir() and all((destination / _safe_relative(path)).is_file() for path in required):
            sources = _read_materialized_sources(destination)
            print("  reusing materialized snapshot", flush=True)
        else:
            sources = fetch_source_tree(
                owner, repo, commit, required_paths=required,
                max_background_blob_bytes=args.max_source_bytes,
                max_files=args.max_files, max_workers=args.fetch_workers,
            )
        missing = required - set(sources)
        if missing:
            raise ValueError(f"missing required paths for {repository}@{commit}: {sorted(missing)}")
        _write_sources(destination, sources)
        for case in snapshot_cases:
            case["input"]["workspace_root"] = str(destination.relative_to(ROOT)).replace("\\", "/")
            target_path = case["input"]["target_path"]
            truth = truths[case["case_id"]]
            start, end = _resolve_target(
                sources[target_path], target_path, truth.get("target_source_sha256"),
                truth.get("target_function_name"),
            )
            truth["target_start_line"] = start
            truth["target_end_line"] = end
            case["input"]["target_start_line"] = start
            case["input"]["target_end_line"] = end
    write_jsonl(args.cases, cases)
    write_jsonl(args.ground_truth, truths.values())
    print(f"Materialized {len(snapshots)} unique repository snapshots")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
