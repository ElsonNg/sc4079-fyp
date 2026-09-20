"""Install and cryptographically lock the local comparison toolchain.

Downloads only official release artifacts and installs Semgrep into an isolated venv
under the ignored comparison-tools directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import venv
from pathlib import Path
from pathlib import PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
TOOLS_ROOT = ROOT / "eval" / "comparison_tools"
LOCK_PATH = ROOT / "eval" / "comparison_tool_lock.json"
CODEQL_TAG = "codeql-bundle-v2.27.0"
OSV_TAG = "v2.6.0"
SEMGREP_VERSION = "1.177.0"
SEMGREP_RULES_COMMIT = "40b8c63f75dc7c22c8a77482d73bfb864b146f7e"
CODEQL_SUITE = "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls"
EXPECTED_CODEQL_RULES = 103
EXPECTED_SEMGREP_YAML_FILES = 203
EXPECTED_SEMGREP_RULES = 212


def _download(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_file():
        return
    temporary = destination.with_suffix(destination.suffix + ".part")
    request = urllib.request.Request(url, headers={"User-Agent": "provtrail-comparison/1"})
    with urllib.request.urlopen(request, timeout=120) as response, temporary.open("wb") as target:
        shutil.copyfileobj(response, target)
    temporary.replace(destination)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _expected_checksum(checksum_file: Path, asset_name: str) -> str:
    for line in checksum_file.read_text(encoding="utf-8").splitlines():
        fields = line.replace("*", " ").split()
        if len(fields) >= 2 and Path(fields[-1]).name == asset_name:
            return fields[0].lower()
    raise ValueError(f"checksum for {asset_name} not found in {checksum_file}")


def _verify(path: Path, expected: str) -> str:
    actual = _sha256(path)
    if actual != expected.lower():
        raise ValueError(f"checksum mismatch for {path.name}: {actual} != {expected}")
    return actual


def _run(command: list[str], cwd: Path | None = None) -> str:
    completed = subprocess.run(
        command, cwd=cwd or ROOT, text=True, encoding="utf-8", errors="replace",
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
    )
    if completed.returncode:
        raise RuntimeError(f"command failed ({completed.returncode}): {' '.join(command)}\n{completed.stdout[-4000:]}")
    return completed.stdout.strip()


def _run_json(command: list[str], cwd: Path | None = None):
    completed = subprocess.run(
        command, cwd=cwd or ROOT, text=True, encoding="utf-8", errors="replace",
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if completed.returncode:
        detail = "\n".join(value for value in (completed.stderr, completed.stdout) if value)
        raise RuntimeError(f"command failed ({completed.returncode}): {' '.join(command)}\n{detail[-4000:]}")
    return json.loads(completed.stdout)


def _safe_extract(bundle: tarfile.TarFile, destination: Path) -> None:
    for member in bundle.getmembers():
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"unsafe archive member: {member.name}")
        if member.issym() or member.islnk():
            link = PurePosixPath(member.linkname)
            if link.is_absolute() or ".." in link.parts:
                raise ValueError(f"unsafe archive link: {member.name} -> {member.linkname}")
    bundle.extractall(destination)


def install_codeql() -> dict:
    asset = "codeql-bundle-win64.tar.gz"
    base = f"https://github.com/github/codeql-action/releases/download/{CODEQL_TAG}"
    archive = TOOLS_ROOT / "downloads" / asset
    checksum = TOOLS_ROOT / "downloads" / f"{asset}.checksum.txt"
    _download(f"{base}/{asset}", archive)
    _download(f"{base}/{asset}.checksum.txt", checksum)
    digest = _verify(archive, _expected_checksum(checksum, asset))
    destination = TOOLS_ROOT / "codeql"
    executable = destination / "codeql" / "codeql.exe"
    if not executable.is_file():
        destination.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive, "r:gz") as bundle:
            _safe_extract(bundle, destination)
    version = _run_json([str(executable), "version", "--format=json"])
    suite_queries = _run_json([
        str(executable), "resolve", "queries", CODEQL_SUITE, "--format=json",
    ])
    return {"tag": CODEQL_TAG, "sha256": digest, "path": str(executable.relative_to(ROOT)),
            "reported_version": version.get("version"), "suite": CODEQL_SUITE,
            # The resolved suite also contains two non-rule summary queries. The
            # runner verifies the SARIF rule registry is exactly 103 on every run.
            "resolved_query_count": len(suite_queries),
            "suite_rule_count": EXPECTED_CODEQL_RULES}


def install_osv() -> dict:
    asset = "osv-scanner_windows_amd64.exe"
    base = f"https://github.com/google/osv-scanner/releases/download/{OSV_TAG}"
    executable = TOOLS_ROOT / "osv-scanner" / "osv-scanner.exe"
    checksums = TOOLS_ROOT / "downloads" / "osv-scanner_SHA256SUMS"
    _download(f"{base}/{asset}", executable)
    _download(f"{base}/osv-scanner_SHA256SUMS", checksums)
    digest = _verify(executable, _expected_checksum(checksums, asset))
    version = _run([str(executable), "--version"])
    return {"tag": OSV_TAG, "sha256": digest, "path": str(executable.relative_to(ROOT)),
            "reported_version": version}


def install_semgrep() -> dict:
    environment = TOOLS_ROOT / "semgrep-venv"
    executable = environment / "Scripts" / "semgrep.exe"
    python = environment / "Scripts" / "python.exe"
    if not executable.is_file():
        venv.EnvBuilder(with_pip=True, clear=False).create(environment)
        _run([str(python), "-m", "pip", "install", "--disable-pip-version-check",
              f"semgrep=={SEMGREP_VERSION}"])
    reported = _run([str(executable), "--version"]).splitlines()[0]
    rules = TOOLS_ROOT / "semgrep-rules"
    if not (rules / ".git").is_dir():
        rules.mkdir(parents=True, exist_ok=True)
        _run(["git", "init"], rules)
        _run(["git", "remote", "add", "origin", "https://github.com/semgrep/semgrep-rules.git"], rules)
        _run(["git", "fetch", "--depth", "1", "origin", SEMGREP_RULES_COMMIT], rules)
        _run(["git", "checkout", "--detach", "FETCH_HEAD"], rules)
    actual_commit = _run(["git", "rev-parse", "HEAD"], rules)
    if actual_commit != SEMGREP_RULES_COMMIT:
        raise ValueError(f"Semgrep rules drift: {actual_commit} != {SEMGREP_RULES_COMMIT}")
    language_dirs = [rules / "javascript", rules / "typescript"]
    selected = sorted({
        path
        for language_dir in language_dirs
        for pattern in ("*.yml", "*.yaml")
        for path in language_dir.rglob(pattern)
    })
    definition_pattern = re.compile(r"^\s*-\s+id\s*:", re.MULTILINE)
    definition_count = sum(
        len(definition_pattern.findall(path.read_text(encoding="utf-8", errors="replace")))
        for path in selected
    )
    if len(selected) != EXPECTED_SEMGREP_YAML_FILES or definition_count != EXPECTED_SEMGREP_RULES:
        raise ValueError(
            "Semgrep rule inventory drift: "
            f"{len(selected)} YAML files/{definition_count} definitions != "
            f"{EXPECTED_SEMGREP_YAML_FILES}/{EXPECTED_SEMGREP_RULES}"
        )
    digest = hashlib.sha256()
    for path in selected:
        digest.update(str(path.relative_to(rules)).replace("\\", "/").encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return {"version": SEMGREP_VERSION, "reported_version": reported,
            "path": str(executable.relative_to(ROOT)),
            "rules_paths": [str(path.relative_to(ROOT)) for path in language_dirs],
            "rules_commit": actual_commit, "yaml_files": len(selected),
            "rule_definitions": definition_count,
            "combined_rules_sha256": digest.hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=LOCK_PATH)
    parser.add_argument("--skip-codeql", action="store_true")
    parser.add_argument("--skip-semgrep", action="store_true")
    parser.add_argument("--skip-osv", action="store_true")
    args = parser.parse_args()
    current = json.loads(args.lock.read_text(encoding="utf-8")) if args.lock.is_file() else {}
    tools = dict(current.get("tools", {}))
    if not args.skip_codeql:
        print(f"Installing CodeQL {CODEQL_TAG}...", flush=True)
        tools["codeql"] = {**tools.get("codeql", {}), **install_codeql()}
    if not args.skip_semgrep:
        print(f"Installing Semgrep {SEMGREP_VERSION}...", flush=True)
        tools["semgrep"] = {**tools.get("semgrep", {}), **install_semgrep()}
        tools["semgrep"]["configuration"] = "pinned-community-javascript-typescript-full"
        for legacy_key in ("rules_path", "security_rule_files", "security_rules_sha256"):
            tools["semgrep"].pop(legacy_key, None)
    if not args.skip_osv:
        print(f"Installing OSV-Scanner {OSV_TAG}...", flush=True)
        tools["osv-scanner"] = {**tools.get("osv-scanner", {}), **install_osv()}
    current.update({"locked": all(name in tools and tools[name].get("path") for name in ("codeql", "semgrep", "osv-scanner")),
                    "platform": sys.platform, "tools": tools})
    args.lock.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(current, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
