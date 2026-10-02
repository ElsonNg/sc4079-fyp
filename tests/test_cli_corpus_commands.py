"""Corpus command dispatch and local artifacts, with external work substituted."""

import json
from pathlib import Path

import numpy as np
import pytest
import requests

from provtrail.cli.commands import corpus
from provtrail.cli.main import main
from provtrail.corpus.models.corpus import BuildResult, CorpusEntry
from provtrail.pipeline.controller.region_extraction import extract_corpus_region_pairs
from provtrail.pipeline.controller.region_retrieval import _region_fingerprint, load_region_index, query_regions
from provtrail.pipeline.integrations import embedding
from provtrail.pipeline.models.region import CandidateRegion


def _entry():
    return CorpusEntry(
        ghsa_id="GHSA-demo", package_name="demo", ecosystem="npm",
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


@pytest.mark.parametrize("options, expected_packages", [
    (["--all"], None),
    (["--package", "axios", "--package", "dompurify"], ("axios", "dompurify")),
])
def test_build_passes_explicit_scope_to_discovery(monkeypatch, tmp_path, options, expected_packages):
    calls = []

    def build(**kwargs):
        calls.append(kwargs["packages"])
        return BuildResult(entries=[])

    monkeypatch.setattr(corpus, "build_corpus_result", build)
    assert main([
        "corpus", "build", *options, "--db-path", str(tmp_path / "corpus.db"),
    ]) == 2
    assert calls == [expected_packages]


@pytest.mark.parametrize("options", [
    [],
    ["--all", "--package", "axios"],
    ["--package", ""],
    ["--package", "   "],
])
def test_build_rejects_invalid_scope_before_discovery(monkeypatch, options):
    def unexpected_build(**kwargs):
        pytest.fail("Missing, conflicting, or empty scope must not start discovery")

    monkeypatch.setattr(corpus, "build_corpus_result", unexpected_build)
    with pytest.raises(SystemExit) as exc:
        main(["corpus", "build", *options])
    assert exc.value.code == 2


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
        "corpus", "build", "--all", "--db-path", str(database),
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


def test_cli_index_round_trips_both_reference_sides_into_scan_retrieval(monkeypatch, tmp_path):
    entries = [_entry()]
    pairs = extract_corpus_region_pairs(entries)
    texts = list(dict.fromkeys(
        region.embedding_text for pair in pairs
        for region in (pair.vulnerable_region, pair.patched_region)
    ))
    vectors = np.eye(len(texts), dtype=np.float32)
    batches = []

    def encode(model, inputs, batch_size=embedding.DEFAULT_EMBEDDING_BATCH_SIZE):
        batches.append(batch_size)
        return vectors[[texts.index(text) for text in inputs]]

    monkeypatch.setattr(corpus, "load_entries", lambda *args: entries)
    monkeypatch.setattr(embedding, "encode", encode)
    monkeypatch.setattr(embedding, "release_models", lambda: None)
    regions = tmp_path / "regions"
    assert main([
        "corpus", "index", "--embed-model", "test-model",
        "--embedding-batch-size", "2", "--region-embeddings-dir", str(regions),
    ]) == 0
    assert batches and set(batches) == {2}
    index = load_region_index(pairs, "test-model", regions)
    assert index is not None
    assert index.index.ntotal == 2 * len(pairs)
    assert index.indexed_pair_ids == [pair.pair_id for pair in pairs for _ in range(2)]
    assert index.indexed_sides == [side for _ in pairs for side in ("vulnerable", "patched")]
    assert not list(tmp_path.rglob("*.npy"))
    for side in ("vulnerable", "patched"):
        candidate = CandidateRegion(region=getattr(pairs[0], f"{side}_region"))
        matches = query_regions([candidate], index, top_k=index.index.ntotal, threshold=0.99)
        assert any(match.pair_id == pairs[0].pair_id and match.reference_side == side for match in matches)

    changed = entries[0].model_copy(update={"patched_function": "function check(x) { return newer(x); }"})
    assert load_region_index(extract_corpus_region_pairs([changed]), "test-model", regions) is None


@pytest.mark.parametrize("option", ["--embeddings-dir", "--skip-region-index"])
def test_function_index_options_are_retired(option):
    with pytest.raises(SystemExit) as error:
        main(["corpus", "index", option])
    assert error.value.code == 2


@pytest.mark.parametrize("mapping", [
    {},
    {"indexed_pair_ids": [], "indexed_sides": []},
    {"indexed_pair_ids": ["wrong-pair"], "indexed_sides": ["vulnerable"]},
])
def test_saved_index_requires_complete_pair_and_side_mapping(tmp_path, mapping):
    pairs = extract_corpus_region_pairs([_entry()])
    metadata = {"fingerprint": _region_fingerprint(pairs, "test-model"), **mapping}
    (tmp_path / "test-model.faiss").write_bytes(b"must not be loaded")
    (tmp_path / "test-model.meta.json").write_text(json.dumps(metadata), encoding="utf-8")
    assert load_region_index(pairs, "test-model", tmp_path) is None
