"""Deduplicate corpus rows into canonical code-change provenance lineages."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from corpus.models.corpus import CorpusEntry
from pipeline.models.provenance import AdvisoryAlias


def _source_digest(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def provenance_lineage_id(entry: CorpusEntry) -> str:
    """Stable identity for one repository-backed vulnerable-to-patched code change."""

    values = (
        entry.repo,
        entry.fix_commit_sha,
        entry.file_path,
        entry.function_name or "",
        _source_digest(entry.vulnerable_function),
        _source_digest(entry.patched_function),
    )
    digest = hashlib.sha256("\0".join(values).encode("utf-8")).hexdigest()
    return f"lineage-{digest}"


def advisory_alias(entry: CorpusEntry) -> AdvisoryAlias:
    return AdvisoryAlias(
        ghsa_id=entry.ghsa_id,
        cve_id=entry.cve_id,
        osv_id=entry.osv_id,
        advisory_title=entry.advisory_title,
        advisory_description=entry.advisory_description,
        advisory_url=entry.advisory_url,
        advisory_references=entry.advisory_references,
        cwes=entry.cwes,
        severity=entry.severity,
        package_name=entry.package_name,
        ecosystem=entry.ecosystem,
        affected_versions=entry.affected_versions,
        fixed_versions=entry.fixed_versions,
    )


@dataclass(frozen=True)
class CorpusLineage:
    lineage_id: str
    representative: CorpusEntry
    entries: tuple[CorpusEntry, ...]
    advisories: tuple[AdvisoryAlias, ...]


def cluster_corpus_entries(entries: list[CorpusEntry]) -> list[CorpusLineage]:
    """Collapse duplicate code pairs while retaining every advisory/package alias."""

    grouped: dict[str, list[CorpusEntry]] = {}
    for entry in entries:
        grouped.setdefault(provenance_lineage_id(entry), []).append(entry)

    lineages: list[CorpusLineage] = []
    for lineage_id, members in grouped.items():
        ordered = sorted(
            members,
            key=lambda item: (
                item.ghsa_id,
                item.package_name,
                item.cve_id or "",
                item.osv_id or "",
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
        lineages.append(
            CorpusLineage(
                lineage_id=lineage_id,
                representative=ordered[0],
                entries=tuple(ordered),
                advisories=tuple(aliases.values()),
            )
        )
    return sorted(lineages, key=lambda item: item.lineage_id)
