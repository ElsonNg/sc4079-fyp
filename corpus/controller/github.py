import base64
import hashlib
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from urllib.parse import quote

import requests
from dotenv import load_dotenv

from corpus.models.commit import GitHubCommitDetail, GitHubCommitFile
from corpus.models.github import GitHubAdvisory, GitHubVulnerability

# Read the project .env while preserving values already set in the process environment.
load_dotenv(Path(__file__).resolve().parents[2] / ".env", override=False)

GITHUB_API_BASE = "https://api.github.com"
GITHUB_RAW_BASE = "https://raw.githubusercontent.com"
GITHUB_API_VERSION = "2022-11-28"

_github_local = threading.local()
_logger = logging.getLogger(__name__)


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
    # A Session is not documented as thread-safe.  Tree downloads use a worker
    # pool, so each worker keeps its own connection pool instead of sharing one.
    session = getattr(_github_local, "session", None)
    if session is None:
        session = requests.Session()
        _github_local.session = session
    return session


class _GitHubRequestGate:
    """Coordinate rate-limit pauses across all download workers."""

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._blocked_until = 0.0

    def wait(self) -> None:
        with self._condition:
            while self._blocked_until > time.time():
                self._condition.wait(timeout=self._blocked_until - time.time())

    def defer(self, seconds: float) -> bool:
        blocked_until = time.time() + max(seconds, 1.0)
        with self._condition:
            if blocked_until <= self._blocked_until:
                return False
            self._blocked_until = blocked_until
            self._condition.notify_all()
            return True


_github_request_gate = _GitHubRequestGate()


def _check_github_rate_limit(response: requests.Response) -> None:
    if response.status_code == 403 and response.headers.get("X-RateLimit-Remaining") == "0":
        reset = response.headers.get("X-RateLimit-Reset", "unknown")
        raise GitHubRateLimitError(f"GitHub API rate limit exceeded, resets at epoch {reset}")


def _rate_limit_delay(response: requests.Response, attempt: int) -> float | None:
    if response.status_code not in {403, 429}:
        return None
    retry_after = response.headers.get("Retry-After")
    if retry_after:
        try:
            return float(retry_after) + 1.0
        except ValueError:
            pass
    if response.headers.get("X-RateLimit-Remaining") == "0":
        try:
            return max(float(response.headers["X-RateLimit-Reset"]) - time.time(), 1.0) + 1.0
        except (KeyError, ValueError):
            return 60.0
    try:
        message = str(response.json().get("message") or "").lower()
    except (ValueError, AttributeError):
        message = ""
    if response.status_code == 429 or "secondary rate limit" in message or "abuse" in message:
        return min(60.0 * (2 ** min(attempt, 4)), 15 * 60.0)
    return None


def _github_get(
    url: str,
    params: dict | None,
    session: requests.Session,
    *,
    allowed_statuses: set[int] | None = None,
) -> requests.Response:
    rate_attempt = 0
    transient_attempt = 0
    while True:
        _github_request_gate.wait()
        try:
            response = session.get(url, headers=_github_headers(), params=params, timeout=30)
        except requests.RequestException:
            if transient_attempt >= 5:
                raise
            delay = min(2 ** transient_attempt, 30)
            transient_attempt += 1
            time.sleep(delay)
            continue
        if allowed_statuses and response.status_code in allowed_statuses:
            return response
        delay = _rate_limit_delay(response, rate_attempt)
        if delay is not None:
            rate_attempt += 1
            if _github_request_gate.defer(delay):
                _logger.warning(
                    "GitHub rate limit reached; pausing all fetch workers for %.0f seconds",
                    delay,
                )
            continue
        if response.status_code in {500, 502, 503, 504} and transient_attempt < 5:
            delay = min(2 ** transient_attempt, 30)
            transient_attempt += 1
            time.sleep(delay)
            continue
        _check_github_rate_limit(response)
        response.raise_for_status()

        # If this successful request consumed the final primary-rate-limit slot,
        # pause before another worker sends a request that is guaranteed to fail.
        if response.headers.get("X-RateLimit-Remaining") == "0":
            try:
                reset_delay = float(response.headers["X-RateLimit-Reset"]) - time.time() + 1.0
            except (KeyError, ValueError):
                reset_delay = 60.0
            _github_request_gate.defer(reset_delay)
        return response


def _github_raw_get(url: str, session: requests.Session) -> requests.Response:
    """Fetch public raw content without spending a core REST API request."""
    rate_attempt = 0
    transient_attempt = 0
    while True:
        _github_request_gate.wait()
        try:
            # Deliberately omit API authentication: source releases used by the
            # corpus are public, and credentials must not be sent to another host.
            response = session.get(url, timeout=60)
        except requests.RequestException:
            if transient_attempt >= 5:
                raise
            delay = min(2 ** transient_attempt, 30)
            transient_attempt += 1
            time.sleep(delay)
            continue
        delay = _rate_limit_delay(response, rate_attempt)
        if delay is not None:
            rate_attempt += 1
            if _github_request_gate.defer(delay):
                _logger.warning(
                    "GitHub download rate limit reached; pausing all fetch workers for %.0f seconds",
                    delay,
                )
            continue
        if response.status_code in {500, 502, 503, 504} and transient_attempt < 5:
            delay = min(2 ** transient_attempt, 30)
            transient_attempt += 1
            time.sleep(delay)
            continue
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
    response = _github_get(url, {"ref": ref}, session, allowed_statuses={404})
    if response.status_code == 404:
        return None
    data = response.json()
    if data.get("encoding") == "base64":
        return base64.b64decode(data["content"]).decode("utf-8")

    # The Contents API omits inline content for files larger than 1 MB and
    # reports ``encoding: none``.  The Git Blobs API still exposes those files,
    # so do not make one large (often unrelated) source file abort the whole
    # package fetch.
    blob_sha = data.get("sha")
    if data.get("encoding") == "none" and blob_sha:
        return fetch_blob_content(
            owner, repo, blob_sha, session=session, context=f"{path}@{ref}"
        )
    raise ValueError(f"Unexpected encoding for {path}@{ref}: {data.get('encoding')}")


def fetch_blob_content(
    owner: str,
    repo: str,
    sha: str,
    *,
    session: requests.Session | None = None,
    context: str | None = None,
) -> str:
    """Return a UTF-8 Git blob, including blobs too large for Contents API."""
    session = session or _get_github_session()
    response = _github_get(
        f"{GITHUB_API_BASE}/repos/{owner}/{repo}/git/blobs/{quote(sha, safe='')}",
        None,
        session,
    )
    data = response.json()
    if data.get("encoding") != "base64":
        location = context or sha
        raise ValueError(
            f"Unexpected Git blob encoding for {location}: {data.get('encoding')}"
        )
    return base64.b64decode(data["content"]).decode("utf-8")


def fetch_raw_file_content(
    owner: str,
    repo: str,
    path: str,
    ref: str,
    *,
    session: requests.Session | None = None,
) -> str:
    """Fetch a public repository file through GitHub's raw-content CDN."""
    session = session or _get_github_session()
    url = (
        f"{GITHUB_RAW_BASE}/{quote(owner, safe='')}/{quote(repo, safe='')}/"
        f"{quote(ref, safe='')}/{quote(path, safe='/')}"
    )
    response = _github_raw_get(url, session)
    return response.content.decode("utf-8")


def fetch_source_tree(
    owner: str,
    repo: str,
    ref: str,
    *,
    package_path: str = "",
    required_paths: Iterable[str] = (),
    max_background_blob_bytes: int | None = None,
    max_files: int | None = None,
    max_workers: int = 1,
    session: requests.Session | None = None,
) -> dict[str, str]:
    """Fetch eligible JS/TS source files from a repository tree at ``ref``.

    The tree is fetched through the GitHub REST API and file bodies through the
    raw-content CDN, avoiding one rate-limited API request per file. Generated output,
    dependencies, tests, examples, and documentation are excluded because Tier 1
    uses them only as package-background noise controls when they are library code.
    """
    if max_workers < 1:
        raise ValueError("max_workers must be at least 1")
    if max_files is not None and max_files < 1:
        raise ValueError("max_files must be at least 1")
    tree_session = session or _get_github_session()
    response = _github_get(
        f"{GITHUB_API_BASE}/repos/{owner}/{repo}/git/trees/{quote(ref, safe='')}"
        f"?recursive=1", None, tree_session
    )
    tree_payload = response.json()
    if tree_payload.get("truncated"):
        raise ValueError(f"GitHub source tree is truncated for {owner}/{repo}@{ref}")
    raw_tree = tree_payload.get("tree", [])
    extensions = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
    excluded = {
        "node_modules", "dist", "build", "coverage", "vendor", "generated",
        "__tests__", "tests", "test", "spec", "examples", "docs", "documentation",
    }
    prefix = package_path.strip("/")
    required = {path.replace("\\", "/").strip("/") for path in required_paths}
    candidates: list[tuple[str, str]] = []
    for item in raw_tree:
        path = str(item.get("path") or "")
        if item.get("type") != "blob" or PurePosixPath(path).suffix.lower() not in extensions:
            continue
        if prefix and not (path == prefix or path.startswith(prefix + "/")):
            continue
        if path not in required and any(
            part.lower() in excluded for part in PurePosixPath(path).parts
        ):
            continue
        size = item.get("size")
        if (
            max_background_blob_bytes is not None
            and path not in required
            and isinstance(size, int)
            and size > max_background_blob_bytes
        ):
            continue
        blob_sha = str(item.get("sha") or "")
        if not blob_sha:
            continue
        candidates.append((path, blob_sha))
    if max_files is not None and len(candidates) > max_files:
        # Content-independent ordering prevents repository tree layout from
        # deciding which background files enter a bounded scan. Required label
        # targets are reserved first so a cap can never invalidate evaluation.
        required_candidates = [item for item in candidates if item[0] in required]
        if len(required_candidates) > max_files:
            raise ValueError(
                f"max_files={max_files} is smaller than the {len(required_candidates)} required paths"
            )
        background_candidates = sorted(
            (item for item in candidates if item[0] not in required),
            key=lambda item: hashlib.sha256(item[0].encode("utf-8")).hexdigest(),
        )[: max_files - len(required_candidates)]
        selected_paths = {item[0] for item in required_candidates + background_candidates}
        candidates = [item for item in candidates if item[0] in selected_paths]
    def fetch(candidate: tuple[str, str]) -> tuple[str, str]:
        path, blob_sha = candidate
        # When no explicit session was supplied, each worker obtains its own
        # thread-local Session. Custom sessions remain useful for tests/callers.
        worker_session = session or _get_github_session()
        try:
            content = fetch_raw_file_content(
                owner, repo, path, ref, session=worker_session
            )
        except requests.HTTPError as exc:
            # Raw delivery can be unavailable for a private repository or an
            # edge-cache miss. The immutable blob SHA remains authoritative.
            if exc.response is None or exc.response.status_code not in {401, 403, 404}:
                raise
            content = fetch_blob_content(
                owner, repo, blob_sha, session=worker_session, context=f"{path}@{ref}"
            )
        return path, content

    fetched: dict[str, str] = {}
    if max_workers == 1 or len(candidates) < 2:
        for candidate in candidates:
            path, content = fetch(candidate)
            fetched[path] = content
    else:
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="github-source") as pool:
            futures = {pool.submit(fetch, candidate): candidate[0] for candidate in candidates}
            try:
                for future in as_completed(futures):
                    path, content = future.result()
                    fetched[path] = content
            except BaseException:
                for future in futures:
                    future.cancel()
                raise
    # Preserve repository-tree ordering regardless of worker completion order.
    return {path: fetched[path] for path, _ in candidates}
