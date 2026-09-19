from pydantic import BaseModel


class GitHubCommitFile(BaseModel):
    filename: str
    status: str
    additions: int = 0
    deletions: int = 0
    changes: int = 0
    patch: str | None = None
    previous_filename: str | None = None


class GitHubCommitDetail(BaseModel):
    sha: str
    parent_shas: list[str] = []
    files: list[GitHubCommitFile] = []


class ExtractedFunctionPair(BaseModel):
    file_path: str
    function_name: str | None = None
    vulnerable_function: str
    patched_function: str
    source_language: str = "javascript"
    patch_hunk: str = ""
    substantive_changed_lines: int = 0
    is_primary: bool = False
