from typing import Literal

from pydantic import BaseModel

from corpus.models.github import CWE


class FunctionFingerprint(BaseModel):
    hashable: bool
    exact_hash: str | None = None
    exact_length: int
    abstracted_hash: str | None = None
    abstracted_length: int


class HashMatch(BaseModel):
    ghsa_id: str
    cve_id: str | None = None
    osv_id: str | None = None
    side: Literal["vulnerable", "patched"]
    match_type: Literal["exact", "abstracted"]
    cwes: list[CWE] = []
    severity: str = "unknown"
    package_name: str | None = None
    ecosystem: str | None = None
    affected_versions: list[str] = []
    fixed_versions: list[str] = []
    repo: str
    fix_commit_sha: str
    file_path: str
    function_name: str | None = None
