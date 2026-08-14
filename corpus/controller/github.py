import base64
import os
from urllib.parse import quote

import requests

from corpus.models.commit import GitHubCommitDetail, GitHubCommitFile
from corpus.models.github import GitHubAdvisory, GitHubVulnerability

GITHUB_API_BASE = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"

_github_session: requests.Session | None = None


class GitHubRateLimitError(RuntimeError):
    pass


def _github_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _get_github_session() -> requests.Session:
    global _github_session
    if _github_session is None:
        _github_session = requests.Session()
    return _github_session


def _check_github_rate_limit(response: requests.Response) -> None:
    if response.status_code == 403 and response.headers.get("X-RateLimit-Remaining") == "0":
        reset = response.headers.get("X-RateLimit-Reset", "unknown")
        raise GitHubRateLimitError(f"GitHub API rate limit exceeded, resets at epoch {reset}")


def _github_get(url: str, params: dict | None, session: requests.Session) -> requests.Response:
    response = session.get(url, headers=_github_headers(), params=params, timeout=30)
    _check_github_rate_limit(response)
    response.raise_for_status()
    return response


def _parse_github_vulnerability(raw: dict) -> GitHubVulnerability:
    package = raw.get("package") or {}
    return GitHubVulnerability(
        package_ecosystem=package.get("ecosystem", ""),
        package_name=package.get("name", ""),
        vulnerable_version_range=raw.get("vulnerable_version_range"),
        first_patched_version=raw.get("first_patched_version"),
        vulnerable_functions=raw.get("vulnerable_functions") or [],
    )


def _parse_github_advisory(raw: dict) -> GitHubAdvisory:
    return GitHubAdvisory(
        ghsa_id=raw["ghsa_id"],
        cve_id=raw.get("cve_id"),
        summary=raw.get("summary") or "",
        description=raw.get("description") or "",
        severity=raw.get("severity") or "unknown",
        cwes=raw.get("cwes") or [],
        withdrawn_at=raw.get("withdrawn_at"),
        references=raw.get("references") or [],
        html_url=raw.get("html_url") or "",
        published_at=raw.get("published_at"),
        updated_at=raw.get("updated_at"),
        vulnerabilities=[
            _parse_github_vulnerability(v) for v in (raw.get("vulnerabilities") or [])
        ],
    )


def fetch_advisories(
    ecosystem: str = "npm",
    affects: str | None = None,
    type: str = "reviewed",
    per_page: int = 100,
    max_pages: int | None = None,
    session: requests.Session | None = None,
) -> list[GitHubAdvisory]:
    session = session or _get_github_session()
    params = {"ecosystem": ecosystem, "type": type, "per_page": per_page}
    if affects:
        params["affects"] = affects

    advisories: list[GitHubAdvisory] = []
    url: str | None = f"{GITHUB_API_BASE}/advisories"
    page_count = 0
    while url:
        response = _github_get(url, params if page_count == 0 else None, session)
        advisories.extend(_parse_github_advisory(raw) for raw in response.json())
        page_count += 1
        if max_pages is not None and page_count >= max_pages:
            break
        url = response.links.get("next", {}).get("url")
    return advisories


def fetch_advisory(ghsa_id: str, session: requests.Session | None = None) -> GitHubAdvisory:
    session = session or _get_github_session()
    response = _github_get(f"{GITHUB_API_BASE}/advisories/{ghsa_id}", None, session)
    return _parse_github_advisory(response.json())


def fetch_commit(
    owner: str, repo: str, sha: str, session: requests.Session | None = None
) -> GitHubCommitDetail:
    session = session or _get_github_session()
    response = _github_get(f"{GITHUB_API_BASE}/repos/{owner}/{repo}/commits/{sha}", None, session)
    raw = response.json()
    return GitHubCommitDetail(
        sha=raw["sha"],
        parent_shas=[p["sha"] for p in raw.get("parents", [])],
        files=[GitHubCommitFile(**f) for f in raw.get("files", [])],
    )


def fetch_file_content(
    owner: str, repo: str, path: str, ref: str, session: requests.Session | None = None
) -> str | None:
    """Returns file content at `ref`, or None if the file doesn't exist there (e.g. added/removed)."""
    session = session or _get_github_session()
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/contents/{quote(path, safe='/')}"
    response = session.get(url, headers=_github_headers(), params={"ref": ref}, timeout=30)
    if response.status_code == 404:
        return None
    _check_github_rate_limit(response)
    response.raise_for_status()
    data = response.json()
    if data.get("encoding") != "base64":
        raise ValueError(f"Unexpected encoding for {path}@{ref}: {data.get('encoding')}")
    return base64.b64decode(data["content"]).decode("utf-8")
