"""HTTP requests for npm release and package metadata."""

from urllib.parse import quote

import requests

NPM_REGISTRY = "https://registry.npmjs.org"
NPMS_API = "https://api.npms.io/v2/package"


class NpmPackageMissing(RuntimeError):
    pass


class NpmReleaseClient:
    def __init__(self, session: requests.Session | None = None) -> None:
        self.session = session or requests.Session()

    def metadata(self, package_name: str) -> dict:
        response = self.session.get(f"{NPM_REGISTRY}/{quote(package_name, safe='')}", timeout=30)
        if response.status_code == 404:
            raise NpmPackageMissing(package_name)
        response.raise_for_status()
        return response.json()

    def tarball(self, url: str) -> bytes:
        response = self.session.get(url, timeout=60)
        response.raise_for_status()
        return response.content

    def dependents(self, package_name: str) -> dict:
        return self.session.get(f"{NPMS_API}/{quote(package_name, safe='')}", timeout=30).json()
