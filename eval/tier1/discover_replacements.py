"""Find advisory-backed Tier 1 replacement candidates without changing the corpus DB."""

from __future__ import annotations

import json
from pathlib import Path

import requests


PACKAGES = (
    "vite", "next", "nuxt", "undici", "webpack-dev-server", "express",
    "@nuxt/kit", "ws", "axios", "lodash",
)
AUDIT = Path("eval/frozen/tier1-advisory-audit-v1/cases.jsonl")


def main() -> None:
    existing = {json.loads(line)["advisory_id"] for line in AUDIT.open(encoding="utf-8")}
    session = requests.Session()
    session.trust_env = False
    for package in PACKAGES:
        response = session.get(
            "https://api.github.com/advisories",
            params={"ecosystem": "npm", "affects": package, "per_page": 100},
            timeout=20,
        )
        response.raise_for_status()
        advisories = response.json()
        fresh = [
            advisory for advisory in advisories
            if advisory["ghsa_id"] not in existing
            and any("/commit/" in ref for ref in advisory.get("references", ()))
        ]
        print(package, "total", len(advisories), "new_with_commits", len(fresh), flush=True)
        for advisory in fresh:
            commits = [ref for ref in advisory["references"] if "/commit/" in ref]
            print(" ", advisory["ghsa_id"], advisory.get("published_at"), len(commits), flush=True)
        print("remaining", response.headers.get("X-RateLimit-Remaining"), flush=True)


if __name__ == "__main__":
    main()
