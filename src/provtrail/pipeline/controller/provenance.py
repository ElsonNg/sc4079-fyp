"""Deduplicate corpus rows into canonical code-change provenance lineages."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from provtrail.corpus.models.corpus import CorpusEntry
from provtrail.shared.metadata import AdvisoryAlias


def _source_digest(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def provenance_lineage_id(entry: CorpusEntry) -> str:
    """Stable identity for an upstream repository/file/function code family."""

    values = (
        entry.origin.repo,
        entry.origin.file_path,
        entry.origin.function_name or "",
    )
    digest = hashlib.sha256("\0".join(values).encode("utf-8")).hexdigest()
    return f"lineage-{digest}"


def fix_boundary_id(entry: CorpusEntry) -> str:
    """Stable identity for one concrete fix inside a lineage."""

    values = (
        provenance_lineage_id(entry),
        entry.origin.fix_commit_sha,
        _source_digest(entry.vulnerable_function),
        _source_digest(entry.patched_function),
    )
    digest = hashlib.sha256("\0".join(values).encode("utf-8")).hexdigest()
    return f"boundary-{digest}"


def advisory_alias(entry: CorpusEntry) -> AdvisoryAlias:
    return entry.advisory



@dataclass(frozen=True)
class CorpusFixBoundary:
    fix_boundary_id: str
    representative: CorpusEntry
    entries: tuple[CorpusEntry, ...]
    advisories: tuple[AdvisoryAlias, ...]


@dataclass(frozen=True)
class CorpusLineage:
    lineage_id: str
    representative: CorpusEntry
    entries: tuple[CorpusEntry, ...]
    advisories: tuple[AdvisoryAlias, ...]
    boundaries: tuple[CorpusFixBoundary, ...]


def cluster_corpus_entries(entries: list[CorpusEntry]) -> list[CorpusLineage]:
    """Group code families, then deduplicate aliases for each concrete fix boundary."""

    grouped: dict[str, list[CorpusEntry]] = {}
    for entry in entries:
        grouped.setdefault(provenance_lineage_id(entry), []).append(entry)

    lineages: list[CorpusLineage] = []
    for lineage_id, members in grouped.items():
        ordered = sorted(
            members,
            key=lambda item: (
                item.advisory.ghsa_id,
                item.advisory.package_name,
                item.advisory.cve_id or "",
                item.advisory.osv_id or "",
            ),
        )
        aliases: dict[tuple[str, str | None, str | None, str, str], AdvisoryAlias] = {}
        for member in ordered:
            alias = advisory_alias(member)
            key = (
                alias.ghsa_id,
                alias.cve_id,
                alias.osv_id,
                alias.package_name or "",
                alias.ecosystem or "",
            )
            aliases.setdefault(key, alias)
        boundary_members: dict[str, list[CorpusEntry]] = {}
        for member in ordered:
            boundary_members.setdefault(fix_boundary_id(member), []).append(member)
        boundaries = []
        for boundary_id, values in sorted(boundary_members.items()):
            boundary_aliases = []
            seen_aliases = set()
            for member in values:
                alias = advisory_alias(member)
                key = (alias.ghsa_id, alias.cve_id, alias.osv_id, alias.package_name, alias.ecosystem)
                if key not in seen_aliases:
                    boundary_aliases.append(alias)
                    seen_aliases.add(key)
            boundaries.append(
                CorpusFixBoundary(
                    fix_boundary_id=boundary_id,
                    representative=values[0],
                    entries=tuple(values),
                    advisories=tuple(boundary_aliases),
                )
            )
        lineages.append(
            CorpusLineage(
                lineage_id=lineage_id,
                representative=ordered[0],
                entries=tuple(ordered),
                advisories=tuple(aliases.values()),
                boundaries=tuple(boundaries),
            )
        )
    return sorted(lineages, key=lambda item: item.lineage_id)
