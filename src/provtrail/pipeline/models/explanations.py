"""Typed contracts for optional local manual-review explanations."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ReviewBrief(BaseModel):
    """Evidence-grounded content returned by the local language model."""

    relevance_tier: Literal[1, 2, 3]
    verdict_rationale: str = Field(min_length=1, max_length=600)
    security_mechanism: str = Field(min_length=1, max_length=600)


class ReviewExplanation(BaseModel):
    """Serializable explanation state attached to a scan finding."""

    status: Literal["generated", "unavailable"]
    model: str
    generated_at: str | None = None
    # Identifies the upstream fix assessed by this saved opinion.
    fix_boundary_id: str | None = None
    relevance_tier: Literal[1, 2, 3] | None = None
    llm_verdict: Literal["flagged", "needs_review", "dismissed"] | None = None
    verdict_rationale: str = ""
    security_mechanism: str = ""
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    review_steps: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    error_code: str | None = None
