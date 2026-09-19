"""Run pinned local scanners and emit normalized, case-addressed findings.

This runner never installs dependencies or executes benchmark source. Tool installation
and rule-pack locking are separate, explicit setup steps.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval.comparison import TOOLS, read_jsonl, write_jsonl
from eval.tool_adapters import load_and_normalize

WORK_ROOT = ROOT / "eval" / "comparison_workspaces"
RAW_ROOT = ROOT / "eval" / "comparison_raw"


def _case_root(case: dict, tool: str) -> Path:
    input_ = case["input"]
    if input_["kind"] == "github_source":
        value = input_.get("workspace_root")
        if not value:
            raise ValueError("real-source cases are not materialized; run materialize_tool_comparison.py")
        return ROOT / value
    if input_["kind"] == "inline_source":
        return WORK_ROOT / ("codeql_detached" if tool == "codeql" else "detached")
    return WORK_ROOT / "metadata"


def _target_relative(case: dict, root: Path, tool: str) -> str:
    input_ = case["input"]
    if input_["kind"] == "github_source":
        return str(input_["target_path"]).replace("\\", "/")
    workspace_path = (
        input_.get("codeql_workspace_path")
        if tool == "codeql" and input_["kind"] == "inline_source"
        else input_["workspace_path"]
    )
    absolute = WORK_ROOT / workspace_path
    return str(absolute.relative_to(root)).replace("\\", "/")


def _run(command: list[str], *, timeout: int, env: dict[str, str] | None = None,
         accepted: set[int] = {0}) -> tuple[bool, str, float]:
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command, cwd=ROOT, env=env, text=True, encoding="utf-8", errors="replace",
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"{type(exc).__name__}: {exc}", time.perf_counter() - started
    elapsed = time.perf_counter() - started
    if completed.returncode not in accepted:
        combined = "\n".join(value for value in (completed.stderr, completed.stdout) if value)
        if (completed.returncode == 128 and "No package sources found" in combined
                and "osv-scanner" in Path(command[0]).name.lower()):
            return True, "", elapsed
        detail = combined.strip()[-2000:]
        return False, f"exit {completed.returncode}: {detail}", elapsed
    return True, "", elapsed


def _commands(tool: str, root: Path, raw_dir: Path, args) -> tuple[list[list[str]], Path, set[int]]:
    output = raw_dir / f"{tool}.json"
    if tool == "provtrail":
        env_python = str(ROOT / ".venv" / "Scripts" / "python.exe")
        return [[env_python, "-m", "cli", "scan", str(root), "--output", str(output),
                 "--html-output", str(raw_dir / "provtrail.html")]], output, {0, 1}
    if tool == "semgrep":
        if not args.semgrep_rules:
            raise ValueError("--semgrep-rules is required for Semgrep")
        configs = [item for path in args.semgrep_rules for item in ("--config", str(path))]
        return [[args.semgrep, "scan", "--json", *configs,
                 "--output", str(output), str(root)]], output, {0}
    if tool == "osv-scanner":
        supported = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"}
        lockfiles = sorted(path for path in root.rglob("*") if path.is_file() and path.name in supported)
        if not lockfiles:
            return [], output, {0}
        lock_args = [item for path in lockfiles for item in ("-L", str(path))]
        return [[args.osv_scanner, "scan", "source", "--format=json", *lock_args,
                 "--output-file", str(output)]], output, {0, 1}
    database = raw_dir / "codeql-db"
    sarif = raw_dir / "codeql.json"
    coverage_bqrs = raw_dir / "target-coverage.bqrs"
    coverage_json = raw_dir / "target-coverage.json"
    common_cache = ROOT / "eval" / "comparison_tools" / "codeql-cache"
    compilation_cache = ROOT / "eval" / "comparison_tools" / "codeql-compile-cache"
    if database.exists() and not args.reuse_codeql_databases:
        raise ValueError(f"CodeQL database already exists: {database}; use a fresh --raw-root")
    if args.reuse_codeql_databases:
        if not database.is_dir() or not sarif.is_file():
            raise ValueError(f"reusable CodeQL database/SARIF missing in {raw_dir}")
        for stale in (coverage_bqrs, coverage_json):
            if stale.is_file():
                stale.unlink()
        setup = []
    else:
        setup = [
            [args.codeql, "database", "create", str(database), "--language=javascript-typescript",
             "--build-mode=none", f"--source-root={root}"],
            [args.codeql, "database", "analyze", str(database), args.codeql_suite,
             "--format=sarif-latest", f"--output={sarif}", "--threads=0"],
        ]
    return [*setup,
        [args.codeql, "query", "run", str(ROOT / "eval" / "codeql" / "TargetCoverage.ql"),
         f"--database={database}", f"--output={coverage_bqrs}",
         f"--common-caches={common_cache}", f"--compilation-cache={compilation_cache}"],
        [args.codeql, "bqrs", "decode", str(coverage_bqrs), "--format=json",
         f"--output={coverage_json}"],
    ], sarif, {0}


def _assign(tool: str, cases: list[dict], findings: list[dict]) -> list[dict]:
    assigned = []
    targets = {
        case["case_id"]: _target_relative(case, _case_root(case, tool), tool)
        for case in cases
    }
    for finding in findings:
        path = str(finding.get("path") or "").replace("\\", "/")
        matched = [
            case for case in cases
            if path == targets[case["case_id"]] or path.endswith("/" + targets[case["case_id"]])
        ]
        # Dependency alerts belong to the scanned snapshot and are attributed by
        # exact advisory/package identity during scoring rather than source span.
        if tool == "osv-scanner" and not matched:
            matched = cases
        for case in matched:
            assigned.append({"record_type": "finding", "tool": tool,
                             "case_id": case["case_id"], **finding})
    return assigned


def _codeql_coverage_rows(raw_dir: Path) -> list[dict]:
    path = raw_dir / "target-coverage.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    result = payload.get("#select", {})
    return [
        {"path": str(row[0]).replace("\\", "/"), "start_line": int(row[1]),
         "end_line": int(row[2]), **({"name": str(row[3] or "")} if len(row) > 3 else {})}
        for row in result.get("tuples", [])
        if len(row) >= 3
    ]


def _codeql_rule_count(path: Path) -> int:
    payload = json.loads(path.read_text(encoding="utf-8"))
    runs = payload.get("runs", [])
    if len(runs) != 1:
        raise ValueError(f"expected one CodeQL SARIF run, found {len(runs)}")
    return len(runs[0].get("tool", {}).get("driver", {}).get("rules", []))


def _codeql_diagnostics(raw_dir: Path, target: str) -> list[str]:
    normalized_target = target.replace("\\", "/").lower()
    matches = []
    for log in sorted((raw_dir / "codeql-db" / "log").glob("database-create-*.log")):
        for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
            normalized = line.replace("\\", "/").lower()
            if normalized_target in normalized and any(
                marker in normalized for marker in ("skip", "error", "fail", "could not")
            ):
                matches.append(line.strip())
    return matches[-5:]


def _codeql_extraction(case: dict, root: Path, coverage: list[dict], raw_dir: Path) -> dict:
    if case["input"]["kind"] == "npm_lockfile":
        return {"target_extracted": True}
    target = _target_relative(case, root, "codeql")
    start = int(case["input"].get(
        "codeql_target_start_line", case["input"].get("target_start_line", 1)
    ))
    end = int(case["input"].get(
        "codeql_target_end_line", case["input"].get("target_end_line", start)
    ))
    matches = [
        row for row in coverage
        if (row["path"] == target or row["path"].endswith("/" + target))
        and row["start_line"] <= end and row["end_line"] >= start
    ]
    if matches:
        return {"target_extracted": True, "extracted_functions": matches}
    diagnostics = _codeql_diagnostics(raw_dir, target)
    return {
        "target_extracted": False,
        "extraction_diagnostics": diagnostics,
        "execution_error": (
            "target_not_extracted: " + diagnostics[-1]
            if diagnostics else
            f"target_not_extracted: no extracted function overlaps {target}:{start}-{end}"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, default=ROOT / "eval" / "comparison_cases.jsonl")
    parser.add_argument("--tool-lock", type=Path, default=ROOT / "eval" / "comparison_tool_lock.json")
    parser.add_argument("--output", type=Path, default=ROOT / "eval" / "comparison_normalized_findings.jsonl")
    parser.add_argument("--raw-root", type=Path, default=RAW_ROOT)
    parser.add_argument("--tool", action="append", choices=TOOLS, dest="tools")
    parser.add_argument("--arm", action="append", choices=("real_source", "detached_clone", "dependency_metadata"), dest="arms")
    parser.add_argument("--case-id", action="append", dest="case_ids")
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--semgrep", default="semgrep")
    parser.add_argument("--semgrep-rules", type=Path, action="append")
    parser.add_argument("--codeql", default="codeql")
    parser.add_argument("--codeql-suite", default="codeql/javascript-queries:codeql-suites/javascript-security-extended.qls")
    parser.add_argument("--codeql-rule-count", type=int, default=103)
    parser.add_argument("--reuse-codeql-databases", action="store_true")
    parser.add_argument("--codeql-allow-minified", action="store_true")
    parser.add_argument("--osv-scanner", default="osv-scanner")
    args = parser.parse_args()
    if args.tool_lock.is_file():
        lock = json.loads(args.tool_lock.read_text(encoding="utf-8"))
        locked_tools = lock.get("tools", {})
        if args.semgrep == "semgrep" and locked_tools.get("semgrep", {}).get("path"):
            args.semgrep = str(ROOT / locked_tools["semgrep"]["path"])
        semgrep_lock = locked_tools.get("semgrep", {})
        if not args.semgrep_rules and semgrep_lock.get("rules_paths"):
            args.semgrep_rules = [ROOT / path for path in semgrep_lock["rules_paths"]]
        elif not args.semgrep_rules and semgrep_lock.get("rules_path"):
            args.semgrep_rules = [ROOT / semgrep_lock["rules_path"]]
        if args.codeql == "codeql" and locked_tools.get("codeql", {}).get("path"):
            args.codeql = str(ROOT / locked_tools["codeql"]["path"])
        args.codeql_rule_count = int(
            locked_tools.get("codeql", {}).get("suite_rule_count", args.codeql_rule_count)
        )
        if args.osv_scanner == "osv-scanner" and locked_tools.get("osv-scanner", {}).get("path"):
            args.osv_scanner = str(ROOT / locked_tools["osv-scanner"]["path"])
    tools = args.tools or list(TOOLS)
    if args.reuse_codeql_databases and tools != ["codeql"]:
        parser.error("--reuse-codeql-databases requires exactly --tool codeql")
    cases = read_jsonl(args.cases)
    if args.arms:
        cases = [case for case in cases if case["arm"] in set(args.arms)]
    if args.case_ids:
        requested = set(args.case_ids)
        cases = [case for case in cases if case["case_id"] in requested]
        missing = requested - {case["case_id"] for case in cases}
        if missing:
            parser.error(f"unknown or filtered --case-id values: {sorted(missing)}")
    records: list[dict] = []
    env = os.environ.copy()
    env.setdefault("HF_HUB_OFFLINE", "1")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    # Since CodeQL 2.24, files with average line lengths above 200 are skipped.
    # Use the override for targeted retries when the coverage gate identifies a
    # labelled minified source; enabling it for every large repository is costly.
    if args.codeql_allow_minified:
        env["CODEQL_EXTRACTOR_JAVASCRIPT_ALLOW_MINIFIED_FILES"] = "true"
    else:
        env.pop("CODEQL_EXTRACTOR_JAVASCRIPT_ALLOW_MINIFIED_FILES", None)
    for tool in tools:
        grouped: dict[Path, list[dict]] = defaultdict(list)
        for case in cases:
            grouped[_case_root(case, tool).resolve()].append(case)
        for index, (root, root_cases) in enumerate(sorted(grouped.items(), key=lambda item: str(item[0])), start=1):
            run_id = f"{tool}-{index:03d}"
            raw_dir = args.raw_root / run_id
            raw_dir.mkdir(parents=True, exist_ok=args.reuse_codeql_databases)
            print(f"[{tool} {index}/{len(grouped)}] {root}", flush=True)
            try:
                commands, output, accepted = _commands(tool, root, raw_dir, args)
                elapsed = 0.0
                ok, error = True, ""
                for command in commands:
                    step_ok, step_error, step_elapsed = _run(
                        command, timeout=args.timeout, env=env, accepted=accepted
                    )
                    elapsed += step_elapsed
                    if not step_ok:
                        ok, error = False, step_error
                        break
                if tool == "codeql" and ok:
                    actual_rules = _codeql_rule_count(output)
                    if actual_rules != args.codeql_rule_count:
                        raise ValueError(
                            f"CodeQL suite drift: SARIF has {actual_rules} rules; "
                            f"expected {args.codeql_rule_count}"
                        )
                normalized = load_and_normalize(tool, output) if ok and output.exists() else []
                coverage = _codeql_coverage_rows(raw_dir) if tool == "codeql" and ok else []
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                ok, error, elapsed, normalized = False, f"{type(exc).__name__}: {exc}", 0.0, []
            for case in root_cases:
                extraction = (
                    _codeql_extraction(case, root, coverage, raw_dir)
                    if tool == "codeql" and ok else {}
                )
                case_ok = ok and extraction.get("target_extracted", True)
                case_error = extraction.get("execution_error") or error
                records.append({
                    "record_type": "execution", "tool": tool, "case_id": case["case_id"],
                    "run_id": run_id, "completed": case_ok, "elapsed_seconds": elapsed,
                    **extraction,
                    **({"execution_error": case_error} if case_error else {}),
                })
            records.extend(_assign(tool, root_cases, normalized))
            write_jsonl(args.output, records)
    print(f"Wrote {len(records)} normalized records to {args.output}")
    return 0 if all(row.get("completed", True) for row in records) else 1


if __name__ == "__main__":
    raise SystemExit(main())
