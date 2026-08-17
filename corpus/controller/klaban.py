"""Import the manually verified Klaban JavaScript vulnerability dataset."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlparse

from corpus.controller.extraction import compute_diagnostic_lines, extract_commit_refs
from corpus.models.corpus import CorpusEntry
from corpus.models.github import CWE
from pipeline.controller.parsing import extract_function_units


DEFAULT_KLABAN_PATH = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "raw"
    / "kluban"
    / "extracted"
    / "manuallyConfirmedFullVulnDataset.json"
)
KLABAN_ID_PREFIX = "KLABAN-"

_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
_NON_ID_RE = re.compile(r"[^A-Za-z0-9]+")


@dataclass
class KlabanImportReport:
    records_seen: int = 0
    functions_seen: int = 0
    functions_unconfirmed: int = 0
    functions_missing_vulnerable_source: int = 0
    functions_without_patch: int = 0
    entries_created: int = 0


def _github_file_parts(url: str) -> tuple[str | None, str | None, str | None]:
    """Return (owner/repo, revision, file path) for GitHub raw-file URLs."""
    parsed = urlparse(url)
    parts = [unquote(part) for part in parsed.path.strip("/").split("/") if part]
    if parsed.netloc == "raw.githubusercontent.com" and len(parts) >= 4:
        return f"{parts[0]}/{parts[1]}", parts[2], "/".join(parts[3:])
    if parsed.netloc in {"github.com", "www.github.com"} and len(parts) >= 5 and parts[2] in {"raw", "blob"}:
        return f"{parts[0]}/{parts[1]}", parts[3], "/".join(parts[4:])
    return None, None, None


def _record_id(record: dict, record_index: int) -> str:
    page = str(record.get("page") or "")
    slug = unquote(urlparse(page).path).strip("/").split("/")[-1]
    if not slug:
        slug = str(record.get("CVE") or f"record-{record_index + 1}")
    clean = _NON_ID_RE.sub("-", slug).strip("-").upper()
    return f"{KLABAN_ID_PREFIX}{clean or f'RECORD-{record_index + 1}'}"


def _cwes(record: dict) -> list[CWE]:
    text = " ".join(str(record.get(key) or "") for key in ("CWE", "type"))
    ids = list(dict.fromkeys(match.upper() for match in _CWE_RE.findall(text)))
    return [CWE(cwe_id=cwe_id, name="") for cwe_id in ids]


def _function_name(source: str, affected_index: int, used_names: set[str]) -> str:
    units = extract_function_units(source)
    base = units[0].name if units else None
    base = base or f"<anonymous:{affected_index + 1}>"
    name = base
    suffix = 2
    while name in used_names:
        name = f"{base}#{suffix}"
        suffix += 1
    used_names.add(name)
    return name


def _references(record: dict, file_record: dict) -> list[str]:
    values = [
        record.get("page"),
        record.get("link"),
        file_record.get("link"),
        file_record.get("fixedLink"),
    ]
    return list(dict.fromkeys(str(value) for value in values if value))


def parse_klaban_corpus(path: Path | str = DEFAULT_KLABAN_PATH) -> tuple[list[CorpusEntry], KlabanImportReport]:
    """Parse confirmed Klaban functions into the application's canonical corpus model.

    Klaban contains both commit-backed function pairs and vulnerable-only functions.
    The latter are retained with an empty patched side: retrieval and vulnerable-side
    hashes remain useful, while diagnostics correctly describe a pure deletion.
    """
    source_path = Path(path)
    payload = json.loads(source_path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("Klaban dataset must be a JSON array")

    entries: list[CorpusEntry] = []
    report = KlabanImportReport(records_seen=len(payload))
    seen_record_ids: dict[str, int] = {}

    for record_index, record in enumerate(payload):
        if not isinstance(record, dict):
            raise ValueError(f"Klaban record {record_index} must be an object")
        base_id = _record_id(record, record_index)
        occurrence = seen_record_ids.get(base_id, 0) + 1
        seen_record_ids[base_id] = occurrence
        advisory_id = base_id if occurrence == 1 else f"{base_id}-{occurrence}"

        commit_refs = extract_commit_refs([str(record.get("link") or "")])
        commit_repo = f"{commit_refs[0][0]}/{commit_refs[0][1]}" if commit_refs else None
        commit_sha = commit_refs[0][2] if commit_refs else None
        title = str(record.get("vulnType") or record.get("type") or record.get("name") or "Klaban vulnerability").strip()
        cve = str(record.get("CVE") or "").strip() or None
        package = str(record.get("packageName") or "").strip()
        version_range = str(record.get("versions") or "").strip()

        for file_index, file_record in enumerate(record.get("files") or []):
            vulnerable_url = str(file_record.get("link") or "")
            fixed_url = str(file_record.get("fixedLink") or "")
            file_repo, vulnerable_revision, file_path = _github_file_parts(vulnerable_url)
            _, fixed_revision, fixed_path = _github_file_parts(fixed_url)
            repo = commit_repo or file_repo or "unknown/unknown"
            revision = commit_sha or fixed_revision or vulnerable_revision or "unknown"
            path_value = fixed_path or file_path or f"unknown-{file_index + 1}.js"
            used_names: set[str] = set()

            for affected_index, affected in enumerate(file_record.get("affectedFunctions") or []):
                report.functions_seen += 1
                if affected.get("confirmed") is not True:
                    report.functions_unconfirmed += 1
                    continue
                vulnerable = str(affected.get("vulnerable") or "")
                if not vulnerable.strip():
                    report.functions_missing_vulnerable_source += 1
                    continue
                patched = str(affected.get("fixed") or "")
                if not patched.strip():
                    report.functions_without_patch += 1

                entries.append(
                    CorpusEntry(
                        ghsa_id=advisory_id,
                        cve_id=cve,
                        advisory_title=title,
                        advisory_description=str(record.get("details") or "").strip(),
                        advisory_url=str(record.get("page") or ""),
                        advisory_references=_references(record, file_record),
                        cwes=_cwes(record),
                        severity="unknown",
                        package_name=package or repo.split("/", 1)[-1],
                        ecosystem="npm",
                        repo=repo,
                        fix_commit_sha=revision,
                        file_path=path_value,
                        function_name=_function_name(vulnerable, affected_index, used_names),
                        vulnerable_function=vulnerable,
                        patched_function=patched,
                        diagnostic_lines=compute_diagnostic_lines(vulnerable, patched),
                        affected_versions=[version_range] if version_range else [],
                        fixed_versions=[],
                        osv_confirmed=False,
                    )
                )

    report.entries_created = len(entries)
    return entries, report


def print_klaban_report(report: KlabanImportReport) -> None:
    print("\n=== Klaban import report ===")
    print(f"  records read:                 {report.records_seen}")
    print(f"  functions read:               {report.functions_seen}")
    print(f"  functions rejected:           {report.functions_unconfirmed} (not confirmed)")
    print(f"  functions missing source:     {report.functions_missing_vulnerable_source}")
    print(f"  vulnerable-only functions:    {report.functions_without_patch}")
    print(f"  corpus entries created:       {report.entries_created}")
