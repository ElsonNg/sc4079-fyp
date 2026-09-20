from typing import Literal

from pydantic import BaseModel, Field

from provtrail.shared.metadata import AdvisoryAlias, SourceReference
from provtrail.pipeline.models.records import FlatRecordModel, HASH_MATCH_FIELDS


class FunctionFingerprint(BaseModel):
    hashable: bool
    exact_hash: str | None = None
    exact_length: int
    abstracted_hash: str | None = None
    abstracted_length: int


class HashMatch(FlatRecordModel):
    record_groups = HASH_MATCH_FIELDS

    # Shared code-family identifier, when attribution is available.
    lineage_id: str | None = None
    # Identifier of the specific vulnerable-to-patched transition.
    fix_boundary_id: str | None = None
    # All advisory aliases attached to this boundary, including shared CVEs.
    advisories: list[AdvisoryAlias] = Field(default_factory=list)
    # Reference side matched by the hash: vulnerable or patched.
    side: Literal["vulnerable", "patched"]
    # Hash representation matched: exact or abstracted.
    match_type: Literal["exact", "abstracted"]
    # Primary advisory and package metadata, e.g. GHSA, CVE and affected versions.
    advisory: AdvisoryAlias
    # Upstream repository, fix commit and source location, e.g. "src/parse.js".
    origin: SourceReference
