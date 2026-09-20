"""Build the deterministic ProvTrail/comparator pilot without executing scanners."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval.common import extension_for
from eval.comparison import (
    SCHEMA_VERSION, aliases, codeql_wrap_source, cwe_set, origin_id, origin_key, read_jsonl,
    select_diverse_origins, write_jsonl,
)
from provtrail.pipeline.controller.parsing import extract_function_units

TIER1 = ROOT / "eval" / "tier1_curated_labels.jsonl"
TIER2_POSITIVE = ROOT / "eval" / "llm_transformed_expanded_positive.jsonl"
TIER2_NEGATIVE = ROOT / "eval" / "llm_transformed_expanded_negative.jsonl"
CASES = ROOT / "eval" / "comparison_cases.jsonl"
TRUTH = ROOT / "eval" / "comparison_ground_truth.jsonl"
LOCK = ROOT / "eval" / "comparison_tool_lock.json"
WORK_ROOT = ROOT / "eval" / "comparison_workspaces"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _tier1_by_origin(rows: list[dict]) -> dict[tuple, dict[str, list[dict]]]:
    result: dict[tuple, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        if row.get("tier1_applicable", True):
            result[origin_key(row)][row["expected_status"]].append(row)
    return result


def _tier2_by_origin(rows: list[dict]) -> dict[tuple, list[dict]]:
    result: dict[tuple, list[dict]] = defaultdict(list)
    for row in rows:
        result[origin_key(row)].append(row)
    return result


def _choose(rows: list[dict], clone_type: str | None = None) -> dict:
    scoped = [row for row in rows if clone_type is None or row.get("clone_type") == clone_type]
    values = scoped or rows
    return sorted(values, key=lambda row: (row.get("candidate_id", ""), _digest(row["candidate_source"])))[0]


def _single_function_unit(record: dict) -> bool:
    extension = extension_for(record.get("source_language", "javascript"))
    return len(extract_function_units(record["candidate_source"], filename=f"candidate{extension}")) == 1


def _catalog(tier1: list[dict], positive: list[dict], negative: list[dict]) -> list[dict]:
    t1 = _tier1_by_origin(tier1)
    pos = _tier2_by_origin(positive)
    neg = _tier2_by_origin(negative)
    catalog = []
    for key in sorted(set(t1) & set(pos) & set(neg), key=repr):
        eligible_positive = [row for row in pos[key] if _single_function_unit(row)]
        eligible_negative = [row for row in neg[key] if _single_function_unit(row)]
        if not eligible_positive or not eligible_negative:
            continue
        probe = eligible_positive[0]
        vulnerable_hash = probe.get("vulnerable_source_sha256")
        patched_hash = probe.get("patched_source_sha256")
        vulnerable = [r for r in t1[key].get("flagged", []) if r.get("target_source_sha256") == vulnerable_hash]
        fixed = [r for r in t1[key].get("cleared", []) if r.get("target_source_sha256") == patched_hash]
        if not vulnerable or not fixed:
            continue
        language = probe.get("source_language")
        if language not in {"javascript", "typescript"}:
            continue
        catalog.append({
            "ghsa_id": key[0], "file_path": key[1], "function_name": key[2],
            "source_language": language,
            "package_name": probe["package_name"],
            "category": probe.get("category", "other"),
            "cwes": sorted(cwe_set(probe.get("cwes", []))),
            "tier1_vulnerable": sorted(vulnerable, key=lambda r: (r.get("version", ""), r.get("source_commit", "")))[0],
            "tier1_fixed": sorted(fixed, key=lambda r: (r.get("version", ""), r.get("source_commit", "")))[0],
            "tier2_positive": eligible_positive, "tier2_negative": eligible_negative,
            "reference": probe,
        })
    return catalog


def _case(case_id: str, oid: str, arm: str, language: str, input_: dict) -> dict:
    return {"schema": SCHEMA_VERSION, "case_id": case_id, "origin_id": oid,
            "arm": arm, "source_language": language, "input": input_}


def _truth(case: dict, selected: dict, expected: str, *, path: str | None = None,
           source: str | None = None, target_hash: str | None = None) -> dict:
    lines = source.count("\n") + 1 if source is not None else None
    return {
        "schema": SCHEMA_VERSION, "case_id": case["case_id"], "origin_id": case["origin_id"],
        "expected_status": expected, "ghsa_id": selected["ghsa_id"],
        "advisory_aliases": aliases(selected["reference"]), "cwes": selected["cwes"],
        "target_path": path, "target_start_line": 1 if source is not None else None,
        "target_end_line": lines, "target_source_sha256": target_hash or (_digest(source) if source else None),
        "target_function_name": selected.get("function_name"),
    }


def _lockfile(package: str, version: str) -> dict:
    return {
        "name": "provtrail-comparison-fixture", "version": "1.0.0", "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {"name": "provtrail-comparison-fixture", "version": "1.0.0", "dependencies": {package: version}},
            f"node_modules/{package}": {"version": version},
        },
        "dependencies": {package: {"version": version}},
    }


def build(count: int, seed: int, materialize: bool) -> tuple[list[dict], list[dict], dict]:
    catalog = _catalog(read_jsonl(TIER1), read_jsonl(TIER2_POSITIVE), read_jsonl(TIER2_NEGATIVE))
    selected = select_diverse_origins(catalog, count, seed=seed)
    cases, truths = [], []
    serial = 0
    detached_files: list[tuple[Path, str]] = []
    codeql_detached_files: list[tuple[Path, str]] = []
    metadata_files: list[tuple[Path, dict]] = []
    for index, row in enumerate(selected):
        oid = origin_id(origin_key(row))
        clone_type = "type_3" if index % 2 == 0 else "type_4"
        transformed_vulnerable = _choose(row["tier2_positive"], clone_type)
        transformed_patched = _choose(row["tier2_negative"], clone_type)
        variants = [
            ("real_source", "vulnerable", row["tier1_vulnerable"], None),
            ("real_source", "patched", row["tier1_fixed"], None),
            ("detached_clone", "vulnerable", transformed_vulnerable, transformed_vulnerable["candidate_source"]),
            ("detached_clone", "patched", transformed_patched, transformed_patched["candidate_source"]),
            ("dependency_metadata", "vulnerable", row["tier1_vulnerable"], None),
            ("dependency_metadata", "patched", row["tier1_fixed"], None),
        ]
        for arm, expected, record, source in variants:
            serial += 1
            case_id = f"CMP{serial:04d}"
            extension = extension_for(row["source_language"])
            if arm == "real_source":
                input_ = {"kind": "github_source", "repository": record["source_repo"],
                          "commit_sha": record["source_commit"], "target_path": record["corpus_file_path"]}
                path = record["corpus_file_path"]
            elif arm == "detached_clone":
                relative = f"detached/src/{case_id}{extension}"
                codeql_relative = f"codeql_detached/src/{case_id}{extension}"
                wrapped = codeql_wrap_source(source, row["source_language"])
                input_ = {
                    "kind": "inline_source", "workspace_path": relative, "source": source,
                    "target_start_line": 1, "target_end_line": source.count("\n") + 1,
                    "codeql_workspace_path": codeql_relative,
                    "codeql_target_start_line": wrapped["target_start_line"],
                    "codeql_target_end_line": wrapped["target_end_line"],
                    "codeql_wrapper_kind": wrapped["wrapper_kind"],
                }
                path = f"src/{case_id}{extension}"
                detached_files.append((WORK_ROOT / relative, source))
                codeql_detached_files.append((WORK_ROOT / codeql_relative, wrapped["source"]))
            else:
                relative = f"metadata/{case_id}/package-lock.json"
                version = str(record["version"])
                input_ = {"kind": "npm_lockfile", "workspace_path": relative,
                          "package": row["package_name"], "version": version}
                path = relative
                metadata_files.append((WORK_ROOT / relative, _lockfile(row["package_name"], version)))
            case = _case(case_id, oid, arm, row["source_language"], input_)
            cases.append(case)
            truth = _truth(
                case, row, expected, path=path, source=source,
                target_hash=record.get("target_source_sha256") if arm == "real_source" else None,
            )
            if arm == "detached_clone":
                truth["tool_targets"] = {"codeql": {
                    "path": f"src/{case_id}{extension}",
                    "start_line": input_["codeql_target_start_line"],
                    "end_line": input_["codeql_target_end_line"],
                    "wrapper_kind": input_["codeql_wrapper_kind"],
                }}
            truths.append(truth)
    if materialize:
        for generated in (WORK_ROOT / "detached", WORK_ROOT / "codeql_detached", WORK_ROOT / "metadata"):
            if generated.is_dir():
                shutil.rmtree(generated)
        for path, source in detached_files:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source.rstrip() + "\n", encoding="utf-8")
        for path, source in codeql_detached_files:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source, encoding="utf-8")
        for path, payload in metadata_files:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        metadata_root = WORK_ROOT / "metadata"
        metadata_root.mkdir(parents=True, exist_ok=True)
        (metadata_root / "index.js").write_text(
            "export function comparisonMetadataControl() { return true; }\n", encoding="utf-8"
        )
        detached_root = WORK_ROOT / "detached"
        detached_root.mkdir(parents=True, exist_ok=True)
        (detached_root / "package.json").write_text(
            json.dumps({"name": "provtrail-detached-comparison", "private": True}, indent=2) + "\n",
            encoding="utf-8",
        )
    metadata = {
        "schema": SCHEMA_VERSION, "seed": seed, "origin_count": count,
        "case_count": len(cases), "catalog_origin_count": len(catalog),
        "selection": [origin_id(origin_key(row)) for row in selected],
    }
    return cases, truths, metadata


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--origins", type=int, default=15, choices=(15, 50))
    parser.add_argument("--seed", type=int, default=4079)
    parser.add_argument("--no-materialize", action="store_true")
    parser.add_argument("--cases", type=Path, default=CASES)
    parser.add_argument("--ground-truth", type=Path, default=TRUTH)
    parser.add_argument("--tool-lock", type=Path, default=LOCK)
    args = parser.parse_args()
    cases, truths, metadata = build(args.origins, args.seed, not args.no_materialize)
    write_jsonl(args.cases, cases)
    write_jsonl(args.ground_truth, truths)
    previous = json.loads(args.tool_lock.read_text(encoding="utf-8")) if args.tool_lock.is_file() else {}
    previous_tools = previous.get("tools", {})
    configurations = {
        "provtrail": "production-fp32-fallback-off",
        "semgrep": "pinned-community-javascript-typescript-full",
        "codeql": "javascript-typescript/security-extended",
        "osv-scanner": "v2-source-recursive",
    }
    tools = {
        name: {"configuration": configuration, **previous_tools.get(name, {})}
        for name, configuration in configurations.items()
    }
    lock = {**previous, **metadata, "locked": all(
        tools.get(name, {}).get("path") for name in ("semgrep", "codeql", "osv-scanner")
    ), "tools": tools}
    args.tool_lock.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metadata, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
