import requests

from provtrail.corpus.models.osv import OSVBatchResult, OSVVulnerability

OSV_API_BASE = "https://api.osv.dev"
OSV_QUERYBATCH_CHUNK_SIZE = 1000

_osv_session: requests.Session | None = None


def _get_osv_session() -> requests.Session:
    global _osv_session
    if _osv_session is None:
        _osv_session = requests.Session()
    return _osv_session


def _osv_querybatch(
    queries: list[dict], session: requests.Session | None = None
) -> list[OSVBatchResult]:
    session = session or _get_osv_session()
    results: list[OSVBatchResult] = []
    for i in range(0, len(queries), OSV_QUERYBATCH_CHUNK_SIZE):
        chunk = queries[i : i + OSV_QUERYBATCH_CHUNK_SIZE]
        response = session.post(
            f"{OSV_API_BASE}/v1/querybatch", json={"queries": chunk}, timeout=30
        )
        response.raise_for_status()
        results.extend(
            OSVBatchResult(**raw) for raw in response.json().get("results", [])
        )
    return results


def fetch_osv_by_commits(
    shas: list[str], session: requests.Session | None = None
) -> list[OSVBatchResult]:
    queries = [{"commit": sha} for sha in shas]
    return _osv_querybatch(queries, session)


def fetch_osv_by_versions(
    package_versions: list[tuple[str, str, str]],
    session: requests.Session | None = None,
) -> list[OSVBatchResult]:
    queries = [
        {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
        for name, ecosystem, version in package_versions
    ]
    return _osv_querybatch(queries, session)


def fetch_osv_vuln(vuln_id: str, session: requests.Session | None = None) -> OSVVulnerability:
    session = session or _get_osv_session()
    response = session.get(f"{OSV_API_BASE}/v1/vulns/{vuln_id}", timeout=30)
    response.raise_for_status()
    return OSVVulnerability(**response.json())


def fetch_osv_single(
    commit: str | None = None,
    package: str | None = None,
    ecosystem: str | None = None,
    version: str | None = None,
    session: requests.Session | None = None,
) -> list[OSVVulnerability]:
    has_commit = commit is not None
    has_version = package is not None and ecosystem is not None and version is not None
    if has_commit == has_version:
        raise ValueError(
            "fetch_osv_single requires exactly one of: commit, or (package, ecosystem, version)"
        )

    session = session or _get_osv_session()
    body = (
        {"commit": commit}
        if has_commit
        else {"version": version, "package": {"name": package, "ecosystem": ecosystem}}
    )
    # next_page_token is intentionally not looped here: this function is only used for the
    # small, known-result-set bootstrap validation (module 1's two known GHSA entries), not
    # for cases expecting more results than fit on one page.
    response = session.post(f"{OSV_API_BASE}/v1/query", json=body, timeout=30)
    response.raise_for_status()
    return [OSVVulnerability(**raw) for raw in response.json().get("vulns", [])]
