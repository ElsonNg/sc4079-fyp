from typing import Literal

from pydantic import BaseModel


class AlignmentOp(BaseModel):
    kind: Literal["match", "gap", "span_merge"]
    a_start: int
    a_end: int
    b_start: int
    b_end: int
    a_lines: list[str] = []
    b_lines: list[str] = []
    score: float


class Alignment(BaseModel):
    ops: list[AlignmentOp] = []
    raw_score: float
    normalized_score: float
    a_length: int
    b_length: int
