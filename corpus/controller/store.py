import json
import sqlite3
from pathlib import Path

from corpus.models.corpus import CorpusEntry, DiagnosticLine
from corpus.models.github import CWE

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "corpus.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS corpus_entries (
    ghsa_id TEXT NOT NULL,
    cve_id TEXT,
    osv_id TEXT,
    advisory_title TEXT NOT NULL DEFAULT '',
    advisory_description TEXT NOT NULL DEFAULT '',
    advisory_url TEXT NOT NULL DEFAULT '',
    advisory_references TEXT NOT NULL DEFAULT '[]',
    cwes TEXT NOT NULL DEFAULT '[]',
    severity TEXT NOT NULL DEFAULT 'unknown',
    package_name TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    repo TEXT NOT NULL,
    fix_commit_sha TEXT NOT NULL,
    file_path TEXT NOT NULL,
    function_name TEXT,
    vulnerable_function TEXT NOT NULL,
    patched_function TEXT NOT NULL,
    diagnostic_lines TEXT NOT NULL DEFAULT '[]',
    affected_versions TEXT NOT NULL DEFAULT '[]',
    fixed_versions TEXT NOT NULL DEFAULT '[]',
    osv_confirmed INTEGER NOT NULL DEFAULT 0,
    source_language TEXT NOT NULL DEFAULT 'javascript',
    vulnerable_runtime TEXT,
    patched_runtime TEXT,
    patch_hunk TEXT NOT NULL DEFAULT '',
    native_hash TEXT NOT NULL DEFAULT '',
    normalized_hash TEXT NOT NULL DEFAULT '',
    runtime_hash TEXT NOT NULL DEFAULT '',
    ast_hash TEXT NOT NULL DEFAULT '',
    release_boundary TEXT NOT NULL DEFAULT '{}',
    high_impact INTEGER NOT NULL DEFAULT 0,
    impact_metadata TEXT NOT NULL DEFAULT '{}',
    evidence_label TEXT NOT NULL DEFAULT 'strictly evidence-attributed vulnerable origin',
    primary_evidence INTEGER NOT NULL DEFAULT 1,
    advisory_aliases TEXT NOT NULL DEFAULT '[]',
    boundary_last_affected TEXT NOT NULL DEFAULT '',
    boundary_first_fixed TEXT NOT NULL DEFAULT '',
    UNIQUE (ghsa_id, fix_commit_sha, file_path, function_name, package_name, boundary_last_affected, boundary_first_fixed)
);
"""

_UPSERT_SQL = """
INSERT INTO corpus_entries (
    ghsa_id, cve_id, osv_id, advisory_title, advisory_description, advisory_url,
    advisory_references, cwes, severity, package_name, ecosystem, repo,
    fix_commit_sha, file_path, function_name, vulnerable_function,
    patched_function, diagnostic_lines, affected_versions, fixed_versions, osv_confirmed,
    source_language, vulnerable_runtime, patched_runtime, patch_hunk, native_hash,
    normalized_hash, runtime_hash, ast_hash, release_boundary, high_impact,
    impact_metadata, evidence_label, primary_evidence, advisory_aliases,
    boundary_last_affected, boundary_first_fixed
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (ghsa_id, fix_commit_sha, file_path, function_name, package_name, boundary_last_affected, boundary_first_fixed) DO UPDATE SET
    cve_id=excluded.cve_id, osv_id=excluded.osv_id,
    advisory_title=excluded.advisory_title,
    advisory_description=excluded.advisory_description,
    advisory_url=excluded.advisory_url,
    advisory_references=excluded.advisory_references,
    cwes=excluded.cwes,
    severity=excluded.severity, package_name=excluded.package_name,
    ecosystem=excluded.ecosystem, repo=excluded.repo,
    vulnerable_function=excluded.vulnerable_function,
    patched_function=excluded.patched_function,
    diagnostic_lines=excluded.diagnostic_lines,
    affected_versions=excluded.affected_versions,
    fixed_versions=excluded.fixed_versions,
    osv_confirmed=excluded.osv_confirmed,
    source_language=excluded.source_language,
    vulnerable_runtime=excluded.vulnerable_runtime,
    patched_runtime=excluded.patched_runtime,
    patch_hunk=excluded.patch_hunk,
    native_hash=excluded.native_hash,
    normalized_hash=excluded.normalized_hash,
    runtime_hash=excluded.runtime_hash,
    ast_hash=excluded.ast_hash,
    release_boundary=excluded.release_boundary,
    high_impact=excluded.high_impact,
    impact_metadata=excluded.impact_metadata,
    evidence_label=excluded.evidence_label,
    primary_evidence=excluded.primary_evidence,
    advisory_aliases=excluded.advisory_aliases
"""


def _entry_values(e: CorpusEntry) -> tuple:
    return (
        e.ghsa_id, e.cve_id, e.osv_id, e.advisory_title, e.advisory_description,
        e.advisory_url, json.dumps(e.advisory_references),
        json.dumps([c.model_dump() for c in e.cwes]), e.severity, e.package_name,
        e.ecosystem, e.repo, e.fix_commit_sha, e.file_path, e.function_name,
        e.vulnerable_function, e.patched_function,
        json.dumps([d.model_dump() for d in e.diagnostic_lines]),
        json.dumps(e.affected_versions), json.dumps(e.fixed_versions), int(e.osv_confirmed),
        e.source_language, e.vulnerable_runtime, e.patched_runtime, e.patch_hunk,
        e.native_hash, e.normalized_hash, e.runtime_hash, e.ast_hash,
        json.dumps(e.release_boundary, sort_keys=True), int(e.high_impact),
        json.dumps(e.impact_metadata, sort_keys=True), e.evidence_label, int(e.primary_evidence),
        json.dumps(e.advisory_aliases, sort_keys=True),
        e.release_boundary.get("last_affected") or "", e.release_boundary.get("first_fixed") or "",
    )


def get_connection(db_path: Path | str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute(SCHEMA)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(corpus_entries)")}
    migrations = {
        "advisory_title": "TEXT NOT NULL DEFAULT ''",
        "advisory_description": "TEXT NOT NULL DEFAULT ''",
        "advisory_url": "TEXT NOT NULL DEFAULT ''",
        "advisory_references": "TEXT NOT NULL DEFAULT '[]'",
        "source_language": "TEXT NOT NULL DEFAULT 'javascript'",
        "vulnerable_runtime": "TEXT",
        "patched_runtime": "TEXT",
        "patch_hunk": "TEXT NOT NULL DEFAULT ''",
        "native_hash": "TEXT NOT NULL DEFAULT ''",
        "normalized_hash": "TEXT NOT NULL DEFAULT ''",
        "runtime_hash": "TEXT NOT NULL DEFAULT ''",
        "ast_hash": "TEXT NOT NULL DEFAULT ''",
        "release_boundary": "TEXT NOT NULL DEFAULT '{}'",
        "high_impact": "INTEGER NOT NULL DEFAULT 0",
        "impact_metadata": "TEXT NOT NULL DEFAULT '{}'",
        "evidence_label": "TEXT NOT NULL DEFAULT 'strictly evidence-attributed vulnerable origin'",
        "primary_evidence": "INTEGER NOT NULL DEFAULT 1",
        "advisory_aliases": "TEXT NOT NULL DEFAULT '[]'",
        "boundary_last_affected": "TEXT NOT NULL DEFAULT ''",
        "boundary_first_fixed": "TEXT NOT NULL DEFAULT ''",
    }
    for column, declaration in migrations.items():
        if column not in columns:
            conn.execute(f"ALTER TABLE corpus_entries ADD COLUMN {column} {declaration}")
    _migrate_unique_constraint(conn)
    conn.commit()
    return conn


def _migrate_unique_constraint(conn: sqlite3.Connection) -> None:
    """Rebuild corpus_entries if its UNIQUE index predates package/boundary-scoped identity.

    Older databases were created with UNIQUE (ghsa_id, fix_commit_sha, file_path,
    function_name) only, which silently collapsed distinct entries that share a fix
    commit but differ by package or release boundary (e.g. the same backport commit
    referenced by several version-range advisories). ALTER TABLE cannot change a
    UNIQUE constraint in place, so the table is recreated with the current schema.
    """
    unique_columns: set[str] = set()
    for index_row in conn.execute("PRAGMA index_list(corpus_entries)"):
        if not index_row[2]:  # index_row[2] is the "unique" flag
            continue
        unique_columns |= {info_row[2] for info_row in conn.execute(f"PRAGMA index_info({index_row[1]})")}
    if "boundary_first_fixed" in unique_columns:
        return
    columns = [row[1] for row in conn.execute("PRAGMA table_info(corpus_entries)")]
    column_list = ", ".join(columns)
    conn.execute("ALTER TABLE corpus_entries RENAME TO corpus_entries_pre_identity_fix")
    conn.execute(SCHEMA)
    conn.execute(
        f"INSERT INTO corpus_entries ({column_list}) "
        f"SELECT {column_list} FROM corpus_entries_pre_identity_fix"
    )
    conn.execute("DROP TABLE corpus_entries_pre_identity_fix")


def save_entries(entries: list[CorpusEntry], db_path: Path | str = DEFAULT_DB_PATH) -> None:
    conn = get_connection(db_path)
    with conn:
        for e in entries:
            conn.execute(_UPSERT_SQL, _entry_values(e))
    conn.close()


def replace_entries_by_ghsa_prefix(
    entries: list[CorpusEntry],
    ghsa_prefix: str,
    db_path: Path | str = DEFAULT_DB_PATH,
) -> None:
    """Atomically replace one source namespace while preserving other corpus rows."""
    conn = get_connection(db_path)
    with conn:
        conn.execute(
            "DELETE FROM corpus_entries WHERE substr(ghsa_id, 1, ?) = ?",
            (len(ghsa_prefix), ghsa_prefix),
        )
        for e in entries:
            conn.execute(_UPSERT_SQL, _entry_values(e))
    conn.close()


def load_entries(db_path: Path | str = DEFAULT_DB_PATH) -> list[CorpusEntry]:
    conn = get_connection(db_path)
    cursor = conn.execute("SELECT * FROM corpus_entries")
    columns = [d[0] for d in cursor.description]
    rows = cursor.fetchall()
    conn.close()

    entries = []
    for row in rows:
        d = dict(zip(columns, row))
        entries.append(
            CorpusEntry(
                ghsa_id=d["ghsa_id"],
                cve_id=d["cve_id"],
                osv_id=d["osv_id"],
                advisory_title=d["advisory_title"],
                advisory_description=d["advisory_description"],
                advisory_url=d["advisory_url"],
                advisory_references=json.loads(d["advisory_references"]),
                cwes=[CWE(**c) for c in json.loads(d["cwes"])],
                severity=d["severity"],
                package_name=d["package_name"],
                ecosystem=d["ecosystem"],
                repo=d["repo"],
                fix_commit_sha=d["fix_commit_sha"],
                file_path=d["file_path"],
                function_name=d["function_name"],
                vulnerable_function=d["vulnerable_function"],
                patched_function=d["patched_function"],
                diagnostic_lines=[
                    DiagnosticLine(**dl) for dl in json.loads(d["diagnostic_lines"])
                ],
                affected_versions=json.loads(d["affected_versions"]),
                fixed_versions=json.loads(d["fixed_versions"]),
                osv_confirmed=bool(d["osv_confirmed"]),
                source_language=d.get("source_language", "javascript"),
                vulnerable_runtime=d.get("vulnerable_runtime"),
                patched_runtime=d.get("patched_runtime"),
                patch_hunk=d.get("patch_hunk", ""),
                native_hash=d.get("native_hash", ""),
                normalized_hash=d.get("normalized_hash", ""),
                runtime_hash=d.get("runtime_hash", ""),
                ast_hash=d.get("ast_hash", ""),
                release_boundary=json.loads(d.get("release_boundary") or "{}"),
                high_impact=bool(d.get("high_impact", 0)),
                impact_metadata=json.loads(d.get("impact_metadata") or "{}"),
                evidence_label=d.get("evidence_label", "strictly evidence-attributed vulnerable origin"),
                primary_evidence=bool(d.get("primary_evidence", 1)),
                advisory_aliases=json.loads(d.get("advisory_aliases") or "[]"),
            )
        )
    return entries
