from typing import Literal

from pydantic import BaseModel


class NodeRange(BaseModel):
    """A tree_sitter.Node's own span, in original source coordinates for whichever side
    (a/b) it came from -- never a per-DP-call-local index."""

    node_type: str
    start_byte: int
    end_byte: int
    start_line: int  # 0-indexed, matches FunctionUnit's convention
    end_line: int


class HierarchicalOp(BaseModel):
    """One correspondence at some level of the hierarchical alignment tree -- either a
    sibling-level structural-child pairing, or (when the containing HierarchicalAlignment
    is_leaf) an individual normalized source line. Extends AlignmentOp's kind/score
    contract with absolute position and, only for a recursed match, the nested result."""

    kind: Literal["match", "gap", "span_merge"]
    score: float
    a: NodeRange | None = None  # None only for a b-only gap
    b: NodeRange | None = None  # None only for an a-only gap
    a_lines: list[str] = []
    b_lines: list[str] = []
    children: "HierarchicalAlignment | None" = None
    # Populated only for a recursed match: container-vs-container, or a leaf pair whose
    # combined line count is >1. A trivial 1-line-vs-1-line leaf match is already fully
    # described by this op's own score/a/b/a_lines/b_lines -- a further 1x1 DP call
    # would add no information, so children stays None for that case.


class HierarchicalAlignment(BaseModel):
    """The result of aligning node_a vs node_b -- either their structural children
    (is_leaf=False) or their own normalized lines directly (is_leaf=True, the flat
    alignment base case). raw_score/normalized_score are this level's own sibling
    alignment's Alignment.raw_score/.normalized_score verbatim -- never rolled up from
    descendant scores, since a matched child's score already appears both as its own
    HierarchicalOp.score here and inside its own nested .children; rolling up would
    double-count it and obscure which specific line actually drove a low score."""

    a: NodeRange
    b: NodeRange
    is_leaf: bool
    raw_score: float
    normalized_score: float
    ops: list[HierarchicalOp] = []


HierarchicalOp.model_rebuild()
