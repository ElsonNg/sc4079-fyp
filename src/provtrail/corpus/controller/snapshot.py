"""Immutable, integrity-checked corpus snapshot publication."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from pathlib import Path

from provtrail.corpus.integrations.sqlite_store import save_entries, snapshot_integrity
from provtrail.corpus.models.corpus import BuildResult
from provtrail.paths import data_dir

DEFAULT_SNAPSHOTS_DIR = data_dir() / "snapshots"


class SnapshotIntegrityError(RuntimeError):
    pass


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _entry_identity(entry) -> list[str | None]:
    """The full row identity: matches corpus_entries' UNIQUE constraint in store.py."""
    return [
        entry.advisory.ghsa_id, entry.origin.fix_commit_sha, entry.origin.file_path, entry.origin.function_name,
        entry.advisory.package_name, entry.release_boundary.get("last_affected"), entry.release_boundary.get("first_fixed"),
    ]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _snapshot_id(result: BuildResult) -> str:
    evidence = [
        {
            "identity": _entry_identity(e),
            "native": e.native_hash,
            "boundary": e.release_boundary,
        }
        for e in result.entries
    ]
    stable_source = {k: v for k, v in result.source_manifest.items() if k != "generated_at"}
    return hashlib.sha256(_canonical_json({"source": stable_source, "entries": evidence}).encode()).hexdigest()[:20]


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


def _verify_snapshot(directory: Path, expected_entries: int) -> dict[str, str]:
    required = (
            "corpus.db", "retrieval-index.json", "source-manifest.json", "attrition.json",
            "quarantine.json", "cohorts.json", "source-hashes.json",
        "indexes/native.json",
    )
    for name in required:
        if not (directory / name).is_file():
            raise SnapshotIntegrityError(f"missing artifact: {name}")
    count, integrity = snapshot_integrity(directory / "corpus.db")
    if count != expected_entries or integrity != "ok":
        raise SnapshotIntegrityError("corpus database integrity check failed")
    index = json.loads((directory / "retrieval-index.json").read_text(encoding="utf-8"))
    if len(index.get("entries", [])) != expected_entries:
        raise SnapshotIntegrityError("retrieval index cardinality mismatch")
    return {name: _sha256(directory / name) for name in required}


def promote_snapshot(result: BuildResult, snapshots_dir: Path = DEFAULT_SNAPSHOTS_DIR) -> Path:
    """Build in a sibling staging directory and publish only after all checks pass."""
    if not result.entries:
        raise SnapshotIntegrityError(
            "refusing to promote an empty corpus snapshot; inspect the quarantine ledger"
        )
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    snapshot_id = _snapshot_id(result)
    destination = snapshots_dir / snapshot_id
    if not destination.exists():
        stage = Path(tempfile.mkdtemp(prefix=f".{snapshot_id}.", dir=snapshots_dir))
        try:
            save_entries(result.entries, stage / "corpus.db")
            _write_json(stage / "source-manifest.json", result.source_manifest)
            _write_json(stage / "attrition.json", [r.model_dump(mode="json") for r in result.reports])
            _write_json(stage / "quarantine.json", [q.model_dump(mode="json") for q in result.quarantine])
            _write_json(stage / "cohorts.json", {
                "complete": len(result.entries),
                "high_impact": sum(entry.high_impact for entry in result.entries),
                "languages": {language: sum(e.origin.source_language == language for e in result.entries) for language in sorted({e.origin.source_language for e in result.entries})},
            })
            _write_json(stage / "source-hashes.json", [
                {"identity": _entry_identity(e), "native_sha256": e.native_hash, "patch_sha256": hashlib.sha256(e.patch_hunk.encode()).hexdigest(), "advisory_sha256": hashlib.sha256(_canonical_json({"title": e.advisory.advisory_title, "description": e.advisory.advisory_description, "references": e.advisory.advisory_references, "affected": e.advisory.affected_versions, "fixed": e.advisory.fixed_versions}).encode()).hexdigest()}
                for e in result.entries
            ])
            (stage / "indexes").mkdir()
            _write_json(stage / "indexes" / "native.json", [
                {"hash": entry.native_hash, "identity": _entry_identity(entry)}
                for entry in result.entries
            ])
            _write_json(stage / "retrieval-index.json", {
                "schema": "native-hash-v2",
                "entries": [
                    {"identity": _entry_identity(e), "language": e.origin.source_language, "native_hash": e.native_hash, "native_match_label": "Flagged (Exact)"}
                    for e in result.entries
                ],
            })
            hashes = _verify_snapshot(stage, len(result.entries))
            _write_json(stage / "artifact-manifest.json", {"snapshot_id": snapshot_id, "artifacts": hashes})
            stage.replace(destination)
        except Exception:
            shutil.rmtree(stage, ignore_errors=True)
            raise
    hashes = _verify_snapshot(destination, len(result.entries))
    pointer_tmp = snapshots_dir / ".current.json.tmp"
    _write_json(pointer_tmp, {"snapshot_id": snapshot_id, "path": destination.name, "artifact_hashes": hashes})
    pointer_tmp.replace(snapshots_dir / "current.json")
    return destination
