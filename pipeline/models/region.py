"""Source-backed AST regions and candidate locations."""

from typing import Literal

from pydantic import BaseModel, Field


RegionGranularity = Literal["changed", "block", "context", "function"]


RegionChangeKind = Literal["insertion", "deletion", "replacement", "movement", "mixed", "unknown"]


class SourceSpan(BaseModel):
    start_byte: int
    end_byte: int
    start_line: int
    end_line: int


class AstRegion(BaseModel):
    """A source-backed AST slice with enough context for retrieval and evidence."""

    region_id: str
    source: str
    span: SourceSpan
    granularity: RegionGranularity
    node_type: str
    ast_path: list[str] = Field(default_factory=list)
    ast_shape: list[str] = Field(default_factory=list)
    normalized_tokens: list[str] = Field(default_factory=list)
    calls: list[str] = Field(default_factory=list)
    member_accesses: list[str] = Field(default_factory=list)
    identifiers: list[str] = Field(default_factory=list)
    literals: list[str] = Field(default_factory=list)
    embedding_text: str


class CandidateRegion(BaseModel):
    candidate_id: str | None = None
    function_name: str | None = None
    region: AstRegion
