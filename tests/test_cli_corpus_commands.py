"""Corpus command dispatch and local artifacts, with external work substituted."""

import json
from pathlib import Path

import numpy as np
import pytest
import requests

from cli.commands import corpus
from cli.main import main
from corpus.controller.store import load_entries
from corpus.models.corpus import BuildResult, CorpusEntry


def _entry():
    return CorpusEntry(
        ghsa_id="KLABAN-demo", package_name="demo", ecosystem="npm",
        repo="owner/demo", fix_commit_sha="abc123", file_path="src/check.js",
        function_name="check",
        vulnerable_function="function check(x) { return unsafe(x); }",
        patched_function="function check(x) { return safe(x); }",
    )


def test_build_promotes_snapshot_to_requested_database(monkeypatch, tmp_path, capsys):
    result = BuildResult(entries=[_entry()])
    calls = []

    def build(**kwargs):
        calls.append(kwargs["packages"])
        return result

    def promote(value, directory):
        assert value is result
        snapshot = directory / "snapshot-1"
        snapshot.mkdir(parents=True)
        (snapshot / "corpus.db").write_bytes(b"validated snapshot")
        return snapshot

    monkeypatch.setattr(corpus, "build_corpus_result", build)
    monkeypatch.setattr(corpus, "promote_snapshot", promote)
    database = tmp_path / "active.db"
    assert main([
        "corpus", "build", "--package", "demo", "--db-path", str(database),
        "--snapshots-dir", str(tmp_path / "snapshots"),
    ]) == 0
    assert calls == [("demo",)]
    assert database.read_bytes() == b"validated snapshot"
    assert not database.with_name(".active.db.tmp").exists()
    assert "Promoted immutable snapshot snapshot-1 with 1 entries" in capsys.readouterr().out


@pytest.mark.parametrize("failure", ["discovery", "empty", "integrity"])
def test_failed_build_preserves_active_database(monkeypatch, tmp_path, failure):
    database = tmp_path / "active.db"
    database.write_bytes(b"existing corpus")

    def build(**kwargs):
        if failure == "discovery":
            raise requests.RequestException("unavailable")
        return BuildResult(entries=[] if failure == "empty" else [_entry()])

    def promote(*args):
        assert failure == "integrity"
        raise corpus.SnapshotIntegrityError("invalid snapshot")

    monkeypatch.setattr(corpus, "build_corpus_result", build)
    monkeypatch.setattr(corpus, "promote_snapshot", promote)
    assert main([
        "corpus", "build", "--db-path", str(database),
        "--snapshots-dir", str(tmp_path / "snapshots"),
    ]) == 2
    assert database.read_bytes() == b"existing corpus"


def test_probe_writes_limited_package_selection(monkeypatch, tmp_path):
    def probe(*, include_withdrawn):
        assert include_withdrawn is True
        return {"packages": [
            {"package": "first", "rank": 1, "advisories": 5},
            {"package": "second", "rank": 2, "advisories": 2},
        ]}

    monkeypatch.setattr(corpus, "probe_packages", probe)
    output = tmp_path / "reports" / "probe.json"
    assert main([
        "corpus", "probe", "--limit", "1", "--include-withdrawn", "--output", str(output),
    ]) == 0
    payload = json.loads(output.read_text())
    assert payload["selected_packages"] == ["first"]
    assert len(payload["all_packages"]) == 2
    assert payload["selected_count"] == 1


@pytest.mark.parametrize("skip_index", [True, False])
def test_ingest_saves_entries_and_optionally_indexes(monkeypatch, tmp_path, skip_index):
    calls = []
    monkeypatch.setattr(corpus, "parse_klaban_corpus", lambda path: ([_entry()], object()))
    monkeypatch.setattr(corpus, "print_klaban_report", lambda report: None)
    monkeypatch.setattr(corpus, "index", lambda args: calls.append(args.db_path) or 0)
    database = tmp_path / "corpus.db"
    args = ["corpus", "ingest-klaban", "fixture.json", "--db-path", str(database)]
    assert main(args + (["--skip-index"] if skip_index else [])) == 0
    assert load_entries(database)[0].advisory.ghsa_id == "KLABAN-demo"
    assert calls == ([] if skip_index else [database])


@pytest.mark.parametrize("skip_regions", [True, False])
def test_index_writes_metadata_and_cleans_temporary_vectors(monkeypatch, tmp_path, skip_regions):
    builds = []
    monkeypatch.setattr(corpus, "load_entries", lambda *args: [_entry()])
    monkeypatch.setattr(corpus.embedding, "encode", lambda model, texts, **kwargs: np.ones((len(texts), 4)))
    monkeypatch.setattr(corpus.embedding, "release_models", lambda: None)
    monkeypatch.setenv("KMP_DUPLICATE_LIB_OK", "TRUE")

    def build_index(args, *, check):
        assert check is True
        assert args[1:3] == ["-m", "cli.faiss_builder"]
        assert np.load(args[3]).shape[1] == 4
        Path(args[4]).write_bytes(b"test index")
        builds.append(args[4])

    monkeypatch.setattr(corpus.subprocess, "run", build_index)
    functions = tmp_path / "functions"
    regions = tmp_path / "regions"
    args = [
        "corpus", "index", "--embed-model", "test-model",
        "--embeddings-dir", str(functions), "--region-embeddings-dir", str(regions),
    ]
    assert main(args + (["--skip-region-index"] if skip_regions else [])) == 0
    assert len(builds) == (1 if skip_regions else 2)
    metadata = json.loads((functions / "test-model.meta.json").read_text())
    assert metadata["entries"][0]["ghsa_id"] == "KLABAN-demo"
    assert not list(tmp_path.rglob("*.npy"))
    if not skip_regions:
        metadata = json.loads((regions / "test-model.meta.json").read_text())
        assert metadata["pairs"][0]["ghsa_id"] == "KLABAN-demo"
