"""Extract new advisory-cited function pairs into a review-only JSONL file."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import requests

from provtrail.corpus.controller.extraction import (
    CleanlinessRejection,
    extract_commit_refs,
    extract_function_pairs_from_commit,
)
from provtrail.corpus.integrations.github import fetch_advisories


DEFAULT_OUTPUT = Path("eval/frozen/tier1-replacement-candidates-v1/pairs.jsonl")
AUDIT = Path("eval/frozen/tier1-advisory-audit-v1/cases.jsonl")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--packages", nargs="+", default=["axios", "vite", "undici", "nuxt", "next"])
    parser.add_argument("--max-commits", type=int, default=36)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    existing = {json.loads(line)["advisory_id"] for line in AUDIT.open(encoding="utf-8")}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    done = set()
    if args.output.exists():
        for line in args.output.open(encoding="utf-8"):
            row = json.loads(line)
            done.add((row["advisory_id"], row["fix_commit_sha"]))
    session = requests.Session()
    session.trust_env = False
    count = 0
    for package in args.packages:
        advisories = fetch_advisories(ecosystem="npm", affects=package, session=session)
        print(package, "advisories", len(advisories), flush=True)
        for advisory in advisories:
            if advisory.ghsa_id in existing or advisory.withdrawn_at:
                continue
            for owner, repo, sha in extract_commit_refs(advisory.references):
                if (advisory.ghsa_id, sha) in done:
                    continue
                if count >= args.max_commits:
                    return
                count += 1
                try:
                    pairs, skipped = extract_function_pairs_from_commit(owner, repo, sha, session=session)
                except (CleanlinessRejection, requests.RequestException, ValueError, KeyError) as exc:
                    print("skip", advisory.ghsa_id, sha[:12], type(exc).__name__, str(exc)[:80], flush=True)
                    continue
                print("pair", advisory.ghsa_id, sha[:12], len(pairs), "skipped", skipped, flush=True)
                with args.output.open("a", encoding="utf-8") as handle:
                    for pair in pairs:
                        row = {
                            "advisory_id": advisory.ghsa_id,
                            "advisory_title": advisory.summary,
                            "advisory_description": advisory.description,
                            "advisory_url": advisory.html_url,
                            "advisory_references": advisory.references,
                            "vulnerabilities": [v.model_dump() for v in advisory.vulnerabilities if v.package_name == package],
                            "package": package,
                            "repo": f"{owner}/{repo}",
                            "fix_commit_sha": sha,
                            "file_path": pair.file_path,
                            "function_name": pair.function_name,
                            "source_language": pair.source_language,
                            "vulnerable_function": pair.vulnerable_function,
                            "patched_function": pair.patched_function,
                            "patch_hunk": pair.patch_hunk,
                            "substantive_changed_lines": pair.substantive_changed_lines,
                            "primary_evidence": pair.is_primary,
                        }
                        handle.write(json.dumps(row, ensure_ascii=False) + "\n")
                done.add((advisory.ghsa_id, sha))


if __name__ == "__main__":
    main()
