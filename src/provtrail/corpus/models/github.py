from pydantic import BaseModel


from provtrail.shared.metadata import CWE


class GitHubVulnerability(BaseModel):
    package_ecosystem: str
    package_name: str
    vulnerable_version_range: str | None = None
    first_patched_version: str | None = None
    vulnerable_functions: list[str] = []


class GitHubAdvisory(BaseModel):
    ghsa_id: str
    cve_id: str | None = None
    summary: str = ""
    description: str = ""
    severity: str = "unknown"
    cwes: list[CWE] = []
    withdrawn_at: str | None = None
    references: list[str] = []
    html_url: str = ""
    published_at: str | None = None
    updated_at: str | None = None
    vulnerabilities: list[GitHubVulnerability] = []
