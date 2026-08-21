"""Deterministic npm release and GitHub commit-boundary evidence."""

from __future__ import annotations

import hashlib
import html
import io
import json
import re
import tarfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlparse

import requests

from corpus.controller.github import GITHUB_API_BASE, _github_get
from corpus.models.github import GitHubVulnerability
from corpus.models.osv import OSVVulnerability

NPM_REGISTRY = "https://registry.npmjs.org"
NPMS_API = "https://api.npms.io/v2/package"


class ReleaseEvidenceError(RuntimeError):
    def __init__(self, reason_code: str, detail: str = ""):
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(f"{reason_code}: {detail}" if detail else reason_code)


def _version_key(version: str) -> tuple:
    value = version.strip().lstrip("v")
    main, _, prerelease = value.partition("-")
    fields = main.split("+")[0].split(".")
    if not all(field.isdigit() for field in fields):
        raise ValueError(version)
    nums = tuple(int(field) for field in (fields + ["0", "0"])[:3])
    pre = tuple((0, int(p)) if p.isdigit() else (1, p) for p in re.split(r"[.-]", prerelease))
    return (*nums, 0 if prerelease else 1, pre)


def _normalized_version(version: str | None) -> str | None:
    return version.strip().lstrip("v") if version else None


def version_satisfies_range(version: str, expression: str) -> bool:
    """Evaluate the npm range forms used by GitHub advisories without shelling out."""
    target = _version_key(version)
    expression = html.unescape(expression).strip()
    for alternative in expression.split("||"):
        part = alternative.strip()
        hyphen = re.fullmatch(r"\s*(\S+)\s+-\s+(\S+)\s*", part)
        if hyphen:
            if _version_key(hyphen.group(1)) <= target <= _version_key(hyphen.group(2)):
                return True
            continue
        comparators = re.findall(r"(\^|~|<=|>=|<|>|=)?\s*(v?\d+(?:\.\d+){0,2}(?:-[\w.-]+)?|[xX*])", part)
        if not comparators:
            continue
        accepted = True
        for operator, raw in comparators:
            if raw in {"x", "X", "*"}:
                continue
            base = _version_key(raw)
            if operator == "<": accepted &= target < base
            elif operator == "<=": accepted &= target <= base
            elif operator == ">": accepted &= target > base
            elif operator == ">=": accepted &= target >= base
            elif operator == "^":
                major, minor, patch = base[:3]
                ceiling = (major + 1, 0, 0) if major else ((0, minor + 1, 0) if minor else (0, 0, patch + 1))
                accepted &= target >= base and target[:3] < ceiling
            elif operator == "~":
                accepted &= target >= base and target[:2] < (base[0], base[1] + 1)
            else:
                # Bare partial versions are npm wildcards; fully specified are exact.
                specified = len(raw.lstrip("v").split("-")[0].split("."))
                accepted &= target[:specified] == base[:specified]
        if accepted:
            return True
    return False


def canonical_github_repo(repository: object) -> str | None:
    raw = repository.get("url") if isinstance(repository, dict) else repository
    if not isinstance(raw, str):
        return None
    value = raw.strip().removeprefix("git+").removesuffix(".git")
    value = re.sub(r"^github:", "https://github.com/", value)
    value = re.sub(r"^git@github\.com:", "https://github.com/", value)
    parsed = urlparse(value)
    if parsed.hostname not in {"github.com", "www.github.com"}:
        return None
    parts = [part for part in parsed.path.split("/") if part]
    return "/".join(parts[:2]) if len(parts) >= 2 else None


def validate_osv_agreement(
    ghsa_id: str,
    package_name: str,
    github_vulnerability: GitHubVulnerability,
    osv: OSVVulnerability,
) -> tuple[list[str], list[str]]:
    aliases = {osv.id, *osv.aliases}
    if ghsa_id not in aliases:
        raise ReleaseEvidenceError("osv_alias_mismatch")
    matching = [
        affected for affected in osv.affected
        if affected.package is not None
        and affected.package.name == package_name
        and affected.package.ecosystem.lower() == "npm"
    ]
    if not matching:
        raise ReleaseEvidenceError("osv_package_mismatch")
    raw_affected = {version for affected in matching for version in affected.versions}
    raw_fixed = {
            event.fixed
            for affected in matching
            for osv_range in affected.ranges
            for event in osv_range.events
            if event.fixed
        }
    try:
        affected_versions = sorted(raw_affected, key=_version_key)
        fixed_versions = sorted(raw_fixed, key=_version_key)
    except ValueError as exc:
        raise ReleaseEvidenceError("range_unparseable", str(exc)) from exc
    github_fixed = _normalized_version(github_vulnerability.first_patched_version)
    if not github_vulnerability.vulnerable_version_range:
        raise ReleaseEvidenceError("github_range_missing")
    if not fixed_versions or not github_fixed:
        raise ReleaseEvidenceError("fixed_range_missing")
    if github_fixed not in {_normalized_version(v) for v in fixed_versions}:
        raise ReleaseEvidenceError("range_disagreement")
    if not affected_versions:
        raise ReleaseEvidenceError("affected_versions_missing")
    below_fixed = [v for v in affected_versions if _version_key(v) < _version_key(github_fixed)]
    if not below_fixed:
        raise ReleaseEvidenceError("last_affected_unresolved")
    last_affected = max(below_fixed, key=_version_key)
    if not version_satisfies_range(last_affected, github_vulnerability.vulnerable_version_range):
        raise ReleaseEvidenceError("range_disagreement")
    if version_satisfies_range(github_fixed, github_vulnerability.vulnerable_version_range):
        raise ReleaseEvidenceError("range_disagreement")
    fixed_versions = [github_fixed, *[v for v in fixed_versions if _normalized_version(v) != github_fixed]]
    return affected_versions, fixed_versions


def fetch_npm_metadata(package_name: str, session: requests.Session) -> dict:
    response = session.get(f"{NPM_REGISTRY}/{quote(package_name, safe='')}", timeout=30)
    response.raise_for_status()
    return response.json()


def _tag_commit(owner: str, repo: str, version: str, session: requests.Session) -> str | None:
    for tag in (f"v{version}", version):
        try:
            response = _github_get(
                f"{GITHUB_API_BASE}/repos/{owner}/{repo}/commits/{quote(tag, safe='')}",
                None,
                session,
            )
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                continue
            raise
        return response.json().get("sha")
    return None


def _release_commit(
    metadata: dict, version: str, owner: str, repo: str, package_name: str,
    session: requests.Session,
) -> tuple[str, str, str]:
    release = (metadata.get("versions") or {}).get(version) or {}
    tarball = (release.get("dist") or {}).get("tarball")
    if not tarball:
        raise ReleaseEvidenceError("tarball_missing", version)
    response = session.get(tarball, timeout=60)
    response.raise_for_status()
    artifact_hash = hashlib.sha256(response.content).hexdigest()
    try:
        with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as archive:
            member = archive.getmember("package/package.json")
            stream = archive.extractfile(member)
            manifest = json.load(stream) if stream is not None else {}
    except (tarfile.TarError, KeyError, json.JSONDecodeError, UnicodeError) as exc:
        raise ReleaseEvidenceError("tarball_invalid", version) from exc
    if manifest.get("name") != package_name or _normalized_version(manifest.get("version")) != _normalized_version(version):
        raise ReleaseEvidenceError("tarball_identity_mismatch", version)
    sha = release.get("gitHead") or _tag_commit(owner, repo, version, session)
    if not sha:
        raise ReleaseEvidenceError("release_commit_unresolved", version)
    return sha, tarball, artifact_hash


def _is_ancestor(owner: str, repo: str, older: str, newer: str, session: requests.Session) -> bool:
    if older == newer:
        return True
    response = _github_get(
        f"{GITHUB_API_BASE}/repos/{owner}/{repo}/compare/{older}...{newer}", None, session
    )
    return response.json().get("status") in {"ahead", "identical"}


def resolve_release_boundary(
    package_name: str,
    affected_versions: list[str],
    fixed_versions: list[str],
    fix_commit_sha: str,
    expected_repo: str,
    *,
    session: requests.Session | None = None,
) -> dict:
    session = session or requests.Session()
    metadata = fetch_npm_metadata(package_name, session)
    canonical_repo = canonical_github_repo(metadata.get("repository"))
    if not canonical_repo or canonical_repo.lower() != expected_repo.lower():
        raise ReleaseEvidenceError("repository_mismatch", canonical_repo or "missing")
    fixed = fixed_versions[0]
    candidates = [v for v in affected_versions if _version_key(v) < _version_key(fixed)]
    if not candidates:
        raise ReleaseEvidenceError("last_affected_unresolved")
    last_affected = max(candidates, key=_version_key)
    owner, repo = canonical_repo.split("/", 1)
    vulnerable_sha, vulnerable_tarball, vulnerable_hash = _release_commit(
        metadata, last_affected, owner, repo, package_name, session
    )
    fixed_sha, fixed_tarball, fixed_hash = _release_commit(
        metadata, fixed, owner, repo, package_name, session
    )
    if not _is_ancestor(owner, repo, vulnerable_sha, fix_commit_sha, session):
        raise ReleaseEvidenceError("fix_outside_release_boundary", "fix is not after last affected")
    if not _is_ancestor(owner, repo, fix_commit_sha, fixed_sha, session):
        raise ReleaseEvidenceError("fix_outside_release_boundary", "fix is not in first fixed")
    return {
        "last_affected": last_affected,
        "first_fixed": fixed,
        "last_affected_commit": vulnerable_sha,
        "first_fixed_commit": fixed_sha,
        "fix_commit": fix_commit_sha,
        "vulnerable_tarball": vulnerable_tarball,
        "fixed_tarball": fixed_tarball,
        "vulnerable_artifact_sha256": vulnerable_hash,
        "fixed_artifact_sha256": fixed_hash,
    }


def assess_high_impact(repo: str, package_name: str, *, session: requests.Session | None = None) -> tuple[bool, dict]:
    """Collect post-admission impact metadata; failures never affect admission."""
    session = session or requests.Session()
    metadata: dict = {"direct_dependents": 0, "stars": 0}
    try:
        npm = session.get(f"{NPMS_API}/{quote(package_name, safe='')}", timeout=30).json()
        metadata["direct_dependents"] = int(
            (((npm.get("collected") or {}).get("npm") or {}).get("dependentsCount")) or 0
        )
        owner, name = repo.split("/", 1)
        github = session.get(f"{GITHUB_API_BASE}/repos/{owner}/{name}", timeout=30).json()
        metadata.update(
            stars=int(github.get("stargazers_count") or 0),
            archived=bool(github.get("archived")),
            disabled=bool(github.get("disabled")),
            pushed_at=github.get("pushed_at"),
        )
        now = datetime.now(timezone.utc)
        release_recent = False
        registry = fetch_npm_metadata(package_name, session)
        latest = (registry.get("dist-tags") or {}).get("latest")
        package_time = (registry.get("time") or {}).get(latest) if latest else None
        if package_time:
            release_recent = (now - datetime.fromisoformat(package_time.replace("Z", "+00:00"))).days <= 548
        since = (now - timedelta(days=180)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        commits = session.get(
            f"{GITHUB_API_BASE}/repos/{owner}/{name}/commits",
            params={"since": since}, timeout=30,
        ).json()
        human_recent = any(
            isinstance(commit, dict)
            and ((commit.get("author") or {}).get("type") == "User")
            for commit in commits if isinstance(commits, list)
        )
        issues = session.get(
            f"{GITHUB_API_BASE}/repos/{owner}/{name}/issues",
            params={"state": "all", "per_page": 100, "sort": "created", "direction": "desc"},
            timeout=30,
        ).json()
        response_samples = []
        for issue in issues if isinstance(issues, list) else []:
            if "pull_request" in issue or not issue.get("created_at"):
                continue
            responded = issue.get("closed_at") or issue.get("updated_at")
            if responded:
                delta = datetime.fromisoformat(responded.replace("Z", "+00:00")) - datetime.fromisoformat(issue["created_at"].replace("Z", "+00:00"))
                response_samples.append(delta.days <= 30)
        response_ratio = sum(response_samples) / len(response_samples) if response_samples else 0.0
        metadata["issue_response_within_30_days"] = response_ratio
        issue_response = response_ratio >= 0.70
        metadata["maintenance_signals"] = {
            "release_within_18_months": release_recent,
            "human_activity_within_180_days": human_recent,
            "issue_response_70pct_within_30_days": issue_response,
        }
        active_signals = sum(metadata["maintenance_signals"].values())
        high = (
            metadata["direct_dependents"] >= 100
            and metadata["stars"] >= 500
            and not metadata["archived"]
            and not metadata["disabled"]
            and active_signals >= 2
        )
        return high, metadata
    except (requests.RequestException, ValueError, KeyError, TypeError):
        metadata["collection_error"] = True
        return False, metadata
