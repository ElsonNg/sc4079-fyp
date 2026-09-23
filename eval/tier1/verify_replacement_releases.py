"""Check candidate fix functions against actual npm release tarballs."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path

import requests

from provtrail.corpus.controller.release import _version_key, version_satisfies_range


INPUT = Path("eval/frozen/tier1-replacement-candidates-v1/pairs.jsonl")
OUTPUT = Path("eval/frozen/tier1-replacement-candidates-v1/release-checks.jsonl")
# Selected by line-level review; admission still requires release source checks.
REVIEWED = (
    0, 5, 27, 32, 33, 37, 38, 39, 42, 87, 88, 93, 98, 99, 101,
    102, 103, 104, 105, 106, 107, 108, 110, 111, 117, 120, 126,
    128, 129, 130, 131, 132, 134, 135, 136, 138,
    30, 31, 40, 43, 44, 45, 78, 79, 80, 94, 95, 96, 97, 109,
    112, 114, 123, 124, 125, 137,
)


def main() -> None:
    candidates = [json.loads(line) for line in INPUT.open(encoding="utf-8")]
    session = requests.Session()
    session.trust_env = False
    metadata_cache: dict[str, dict] = {}
    archive_cache: dict[tuple[str, str], tuple[str, dict[str, bytes]]] = {}

    def metadata(package: str) -> dict:
        if package not in metadata_cache:
            response = session.get(f"https://registry.npmjs.org/{package}", timeout=30)
            response.raise_for_status()
            metadata_cache[package] = response.json()
        return metadata_cache[package]

    def archive(package: str, version: str) -> tuple[str, dict[str, bytes]]:
        key = (package, version)
        if key not in archive_cache:
            url = metadata(package)["versions"][version]["dist"]["tarball"]
            response = session.get(url, timeout=60)
            response.raise_for_status()
            content = response.content
            with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tar:
                members = {
                    member.name.removeprefix("package/"): tar.extractfile(member).read()
                    for member in tar.getmembers()
                    if member.isfile() and member.name.startswith("package/")
                }
            archive_cache[key] = hashlib.sha256(content).hexdigest(), members
        return archive_cache[key]

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", encoding="utf-8") as handle:
        for index in REVIEWED:
            candidate = candidates[index]
            package = candidate["package"]
            package_metadata = metadata(package)
            versions = package_metadata["versions"]
            matches = []
            for vulnerability in candidate["vulnerabilities"]:
                fixed = vulnerability["first_patched_version"]
                affected_range = vulnerability["vulnerable_version_range"]
                if not fixed or fixed not in versions:
                    continue
                try:
                    earlier = sorted(
                        (version for version in versions
                         if _version_key(version) < _version_key(fixed)
                         and version_satisfies_range(version, affected_range)),
                        key=_version_key,
                    )
                except ValueError:
                    continue
                if not earlier:
                    continue
                vulnerable = earlier[-1]
                path = candidate["file_path"]
                try:
                    vulnerable_hash, vulnerable_files = archive(package, vulnerable)
                    fixed_hash, fixed_files = archive(package, fixed)
                except (requests.RequestException, tarfile.TarError, KeyError) as exc:
                    matches.append({"fixed_version": fixed, "error": str(exc)[:120]})
                    continue
                vulnerable_source = vulnerable_files.get(path, b"").decode("utf-8", errors="replace")
                fixed_source = fixed_files.get(path, b"").decode("utf-8", errors="replace")
                matches.append({
                    "vulnerable_version": vulnerable,
                    "fixed_version": fixed,
                    "vulnerable_tarball_sha256": vulnerable_hash,
                    "fixed_tarball_sha256": fixed_hash,
                    "file_in_vulnerable_release": bool(vulnerable_source),
                    "file_in_fixed_release": bool(fixed_source),
                    "vulnerable_function_exact": candidate["vulnerable_function"] in vulnerable_source,
                    "patched_function_exact": candidate["patched_function"] in fixed_source,
                    "vulnerable_source_sha256": hashlib.sha256(vulnerable_source.encode()).hexdigest() if vulnerable_source else None,
                    "fixed_source_sha256": hashlib.sha256(fixed_source.encode()).hexdigest() if fixed_source else None,
                })
            result = {
                "candidate_index": index,
                "advisory_id": candidate["advisory_id"],
                "package": package,
                "file_path": candidate["file_path"],
                "function_name": candidate["function_name"],
                "fix_commit_sha": candidate["fix_commit_sha"],
                "release_checks": matches,
            }
            handle.write(json.dumps(result) + "\n")
            print(index, package, candidate["advisory_id"], [
                (item.get("vulnerable_version"), item.get("fixed_version"),
                 item.get("vulnerable_function_exact"), item.get("patched_function_exact"))
                for item in matches
            ], flush=True)


if __name__ == "__main__":
    main()
