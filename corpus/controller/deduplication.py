"""Stable native-source corpus deduplication."""

from __future__ import annotations

import hashlib
import json
import re

from corpus.models.corpus import CorpusEntry
from pipeline.controller.parsing import normalize_source


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _token_form(source: str) -> str:
    return " ".join(re.findall(r"[A-Za-z_$][\w$]*|\d+(?:\.\d+)?|[^\s\w]", source))


def fingerprint_entry(entry: CorpusEntry) -> CorpusEntry:
    entry.native_hash = _hash(entry.vulnerable_function)
    entry.normalized_hash = _hash(_token_form(" ".join(normalize_source(entry.vulnerable_function))))
    # The normalized syntax representation remains native-language only.
    entry.ast_hash = _hash(json.dumps(_token_form(entry.vulnerable_function).split(), separators=(",", ":")))
    if not entry.advisory_aliases:
        entry.advisory_aliases = [{
            "ghsa_id": entry.advisory.ghsa_id, "cve_id": entry.advisory.cve_id, "osv_id": entry.advisory.osv_id,
            "title": entry.advisory.advisory_title, "url": entry.advisory.advisory_url,
        }]
    return entry


def deduplicate_entries(entries: list[CorpusEntry]) -> tuple[list[CorpusEntry], int]:
    """Collapse aliases/backports while retaining different vulnerable-to-fixed boundaries."""
    result: list[CorpusEntry] = []
    seen: dict[tuple, CorpusEntry] = {}
    for entry in sorted(
        (fingerprint_entry(item) for item in entries),
        key=lambda e: (e.advisory.ghsa_id, e.origin.fix_commit_sha, e.origin.file_path, e.origin.function_name or ""),
    ):
        boundary = (
            entry.release_boundary.get("last_affected"),
            entry.release_boundary.get("first_fixed"),
        )
        key = (entry.advisory.package_name, boundary, entry.ast_hash)
        if key in seen:
            existing = seen[key]
            known = {(a.get("ghsa_id"), a.get("cve_id"), a.get("osv_id")) for a in existing.advisory_aliases}
            for alias in entry.advisory_aliases:
                identity = (alias.get("ghsa_id"), alias.get("cve_id"), alias.get("osv_id"))
                if identity not in known:
                    existing.advisory_aliases.append(alias)
                    known.add(identity)
            continue
        seen[key] = entry
        result.append(entry)
    return result, len(entries) - len(result)
