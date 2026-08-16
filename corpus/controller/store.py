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
    UNIQUE (ghsa_id, fix_commit_sha, file_path, function_name)
);
"""

_UPSERT_SQL = """
INSERT INTO corpus_entries (
    ghsa_id, cve_id, osv_id, advisory_title, advisory_description, advisory_url,
    advisory_references, cwes, severity, package_name, ecosystem, repo,
    fix_commit_sha, file_path, function_name, vulnerable_function,
    patched_function, diagnostic_lines, affected_versions, fixed_versions, osv_confirmed
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (ghsa_id, fix_commit_sha, file_path, function_name) DO UPDATE SET
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
    osv_confirmed=excluded.osv_confirmed
"""


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
    }
    for column, declaration in migrations.items():
        if column not in columns:
            conn.execute(f"ALTER TABLE corpus_entries ADD COLUMN {column} {declaration}")
    conn.commit()
    return conn


def save_entries(entries: list[CorpusEntry], db_path: Path | str = DEFAULT_DB_PATH) -> None:
    conn = get_connection(db_path)
    with conn:
        for e in entries:
            conn.execute(
                _UPSERT_SQL,
                (
                    e.ghsa_id,
                    e.cve_id,
                    e.osv_id,
                    e.advisory_title,
                    e.advisory_description,
                    e.advisory_url,
                    json.dumps(e.advisory_references),
                    json.dumps([c.model_dump() for c in e.cwes]),
                    e.severity,
                    e.package_name,
                    e.ecosystem,
                    e.repo,
                    e.fix_commit_sha,
                    e.file_path,
                    e.function_name,
                    e.vulnerable_function,
                    e.patched_function,
                    json.dumps([d.model_dump() for d in e.diagnostic_lines]),
                    json.dumps(e.affected_versions),
                    json.dumps(e.fixed_versions),
                    int(e.osv_confirmed),
                ),
            )
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
            )
        )
    return entries
