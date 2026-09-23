"""Pin repository release commits for the npm-verified replacement functions."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import requests

from provtrail.corpus.integrations.github import fetch_file_content, find_tag_commit


ROOT = Path("eval/frozen/tier1-expansion-v1")
OUTPUT = ROOT / "release-commits.jsonl"


def main() -> None:
    pairs = [json.loads(line) for line in (ROOT / "pairs.jsonl").open(encoding="utf-8")]
    session = requests.Session()
    session.trust_env = False
    metadata: dict[str, dict] = {}
    rows = []
    for pair in pairs:
        package = pair["package"]
        if package not in metadata:
            response = session.get("https://registry.npmjs.org/" + package, timeout=30)
            response.raise_for_status()
            metadata[package] = response.json()
        owner, repo = pair["repo"].split("/", 1)
        for side, version, source_key in (
            ("vulnerable", pair["vulnerable_version"], "vulnerable_function"),
            ("patched", pair["fixed_version"], "patched_function"),
        ):
            release = metadata[package]["versions"][version]
            commit = release.get("gitHead")
            source = None
            if commit:
                source = fetch_file_content(owner, repo, pair["file_path"], commit, session=session)
            if source is None or pair[source_key] not in source:
                tag_commit = find_tag_commit(owner, repo, version, session=session)
                if tag_commit and tag_commit != commit:
                    tagged = fetch_file_content(owner, repo, pair["file_path"], tag_commit, session=session)
                    if tagged and pair[source_key] in tagged:
                        commit, source = tag_commit, tagged
            matched = bool(source and pair[source_key] in source)
            row = {
                "pair_id": pair["pair_id"],
                "side": side,
                "package": package,
                "version": version,
                "repo": pair["repo"],
                "file_path": pair["file_path"],
                "source_commit": commit,
                "source_exact_at_commit": matched,
                "release_file_sha256": hashlib.sha256(source.encode()).hexdigest() if source else None,
                "tarball_url": release["dist"]["tarball"],
            }
            rows.append(row)
            print(pair["pair_id"], side, version, matched, flush=True)
    OUTPUT.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    print("matched", sum(row["source_exact_at_commit"] for row in rows), "/", len(rows))


if __name__ == "__main__":
    main()
