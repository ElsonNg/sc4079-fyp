"""Immutable, integrity-checked corpus snapshot publication."""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import tempfile
from pathlib import Path

from corpus.controller.store import save_entries
from corpus.models.corpus import BuildResult

DEFAULT_SNAPSHOTS_DIR = Path(__file__).resolve().parent.parent / "data" / "snapshots"


class SnapshotIntegrityError(RuntimeError):
    pass


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _snapshot_id(result: BuildResult) -> str:
    evidence = [
        {
            "identity": [e.ghsa_id, e.fix_commit_sha, e.file_path, e.function_name],
            "native": e.native_hash,
            "runtime": e.runtime_hash,
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
        "indexes/native.json", "indexes/type-erased.json",
    )
    for name in required:
        if not (directory / name).is_file():
            raise SnapshotIntegrityError(f"missing artifact: {name}")
    conn = sqlite3.connect(directory / "corpus.db")
    try:
        count = conn.execute("SELECT COUNT(*) FROM corpus_entries").fetchone()[0]
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        conn.close()
    if count != expected_entries or integrity != "ok":
        raise SnapshotIntegrityError("corpus database integrity check failed")
    index = json.loads((directory / "retrieval-index.json").read_text(encoding="utf-8"))
    if len(index.get("entries", [])) != expected_entries:
        raise SnapshotIntegrityError("retrieval index cardinality mismatch")
    return {name: _sha256(directory / name) for name in required}


def promote_snapshot(result: BuildResult, snapshots_dir: Path = DEFAULT_SNAPSHOTS_DIR) -> Path:
    """Build in a sibling staging directory and publish only after all checks pass."""
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
                "languages": {language: sum(e.source_language == language for e in result.entries) for language in sorted({e.source_language for e in result.entries})},
            })
            _write_json(stage / "source-hashes.json", [
                {"identity": [e.ghsa_id, e.fix_commit_sha, e.file_path, e.function_name], "native_sha256": e.native_hash, "runtime_sha256": e.runtime_hash, "patch_sha256": hashlib.sha256(e.patch_hunk.encode()).hexdigest(), "advisory_sha256": hashlib.sha256(_canonical_json({"title": e.advisory_title, "description": e.advisory_description, "references": e.advisory_references, "affected": e.affected_versions, "fixed": e.fixed_versions}).encode()).hexdigest()}
                for e in result.entries
            ])
            (stage / "indexes").mkdir()
            _write_json(stage / "indexes" / "native.json", [
                {"hash": entry.native_hash, "identity": [entry.ghsa_id, entry.fix_commit_sha, entry.file_path, entry.function_name]}
                for entry in result.entries
            ])
            _write_json(stage / "indexes" / "type-erased.json", [
                {"hash": entry.runtime_hash, "identity": [entry.ghsa_id, entry.fix_commit_sha, entry.file_path, entry.function_name], "maximum_label": "Flagged (Inferred)"}
                for entry in result.entries
            ])
            _write_json(stage / "retrieval-index.json", {
                "schema": "native-runtime-hash-v1",
                "entries": [
                    {"identity": [e.ghsa_id, e.fix_commit_sha, e.file_path, e.function_name], "language": e.source_language, "native_hash": e.native_hash, "runtime_hash": e.runtime_hash, "native_match_label": "Flagged (Exact)", "cross_language_match_label": "Flagged (Inferred)"}
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
