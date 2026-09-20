import json

from provtrail.corpus.controller.klaban import KLABAN_ID_PREFIX, parse_klaban_corpus
from provtrail.corpus.integrations.sqlite_store import load_entries, replace_entries_by_ghsa_prefix, save_entries
from provtrail.corpus.models.corpus import CorpusEntry


def _write_dataset(tmp_path):
    path = tmp_path / "klaban.json"
    path.write_text(
        json.dumps(
            [
                {
                    "link": "https://github.com/acme/widget/commit/deadbeef",
                    "page": "https://snyk.io/vuln/SNYK-JS-WIDGET-1234",
                    "CVE": "CVE-2026-1234",
                    "CWE": "CWE-79",
                    "packageName": "widget",
                    "versions": "<2.0.0",
                    "details": "Unsafe rendering.",
                    "vulnType": "Cross-site Scripting",
                    "files": [
                        {
                            "link": "https://github.com/acme/widget/raw/cafebabe/src/render.js",
                            "fixedLink": "https://github.com/acme/widget/raw/deadbeef/src/render.js",
                            "affectedFunctions": [
                                {
                                    "vulnerable": "function render(value) { return value; }",
                                    "fixed": "function render(value) { return escape(value); }",
                                    "confirmed": True,
                                },
                                {
                                    "vulnerable": "value => value",
                                    "fixed": "",
                                    "confirmed": True,
                                },
                                {
                                    "vulnerable": "function ignored() {}",
                                    "fixed": "function ignored() {}",
                                    "confirmed": False,
                                },
                            ],
                        }
                    ],
                }
            ]
        ),
        encoding="utf-8",
    )
    return path


def test_parse_klaban_keeps_only_confirmed_functions_and_provenance(tmp_path):
    entries, report = parse_klaban_corpus(_write_dataset(tmp_path))

    assert len(entries) == 2
    assert report.functions_seen == 3
    assert report.functions_unconfirmed == 1
    assert report.functions_without_patch == 1
    first = entries[0]
    assert first.advisory.ghsa_id == "KLABAN-SNYK-JS-WIDGET-1234"
    assert first.advisory.cve_id == "CVE-2026-1234"
    assert first.advisory.cwes[0].cwe_id == "CWE-79"
    assert first.origin.repo == "acme/widget"
    assert first.origin.fix_commit_sha == "deadbeef"
    assert first.origin.file_path == "src/render.js"
    assert first.origin.function_name == "render"
    assert first.advisory.affected_versions == ["<2.0.0"]
    assert first.diagnostic_lines
    assert entries[1].patched_function == ""
    assert {line.kind for line in entries[1].diagnostic_lines} == {"removed"}


def test_reimport_replaces_only_klaban_namespace(tmp_path):
    database = tmp_path / "corpus.db"
    native = CorpusEntry(
        ghsa_id="GHSA-native",
        package_name="native",
        ecosystem="npm",
        repo="acme/native",
        fix_commit_sha="abc1234",
        file_path="index.js",
        function_name="native",
        vulnerable_function="function native() {}",
        patched_function="function native() {}",
    )
    old_klaban = native.model_copy(update={'advisory': native.advisory.model_copy(update={'ghsa_id': "KLABAN-OLD"})})
    save_entries([native, old_klaban], database)

    imported, _ = parse_klaban_corpus(_write_dataset(tmp_path))
    replace_entries_by_ghsa_prefix(imported, KLABAN_ID_PREFIX, database)

    entries = load_entries(database)
    assert {entry.advisory.ghsa_id for entry in entries} == {
        "GHSA-native",
        "KLABAN-SNYK-JS-WIDGET-1234",
    }
    assert len(entries) == 3
