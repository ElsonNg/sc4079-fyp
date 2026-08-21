from pydantic import BaseModel

from corpus.models.github import CWE


class RetrievalMatch(BaseModel):
    ghsa_id: str
    cve_id: str | None = None
    advisory_title: str = ""
    advisory_description: str = ""
    advisory_url: str = ""
    advisory_references: list[str] = []
    cwes: list[CWE] = []
    severity: str = "unknown"
    repo: str
    fix_commit_sha: str
    file_path: str
    function_name: str | None = None
    similarity: float = 0.0
    source_language: str = "javascript"
    representation: str = "native"
