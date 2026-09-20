"""Compatibility and injected transport contracts for external integrations."""

import subprocess
import sys

import numpy as np
import pytest

from corpus.controller import github as legacy_github
from corpus.controller import osv as legacy_osv
from corpus.controller import store as legacy_store
from corpus.controller.release import ReleaseEvidenceError, fetch_npm_metadata
from corpus.integrations import github, osv, sqlite_store
from pipeline.controller import embedding as legacy_embedding
from pipeline.controller.review_explanation import OllamaExplanationConfig
from pipeline.integrations import embedding, ollama
from pipeline.integrations.vector_index import load_faiss_index


def test_legacy_imports_reference_canonical_integrations():
    assert legacy_github.fetch_source_tree is github.fetch_source_tree
    assert legacy_osv.fetch_osv_vuln is osv.fetch_osv_vuln
    assert legacy_store.load_entries is sqlite_store.load_entries
    assert legacy_embedding.encode is embedding.encode
    assert OllamaExplanationConfig is ollama.OllamaExplanationConfig


@pytest.mark.parametrize("status,expected", [(200, None), (404, "npm_package_missing")])
def test_npm_metadata_preserves_missing_package_behavior_with_injected_session(status, expected):
    class Response:
        status_code = status

        def raise_for_status(self):
            return None

        def json(self):
            return {"name": "@scope/demo"}

    class Session:
        def __init__(self):
            self.calls = []

        def get(self, url, timeout):
            self.calls.append((url, timeout))
            return Response()

    session = Session()
    if expected:
        with pytest.raises(ReleaseEvidenceError) as error:
            fetch_npm_metadata("@scope/demo", session)
        assert error.value.reason_code == expected
    else:
        assert fetch_npm_metadata("@scope/demo", session) == {"name": "@scope/demo"}
    assert session.calls == [("https://registry.npmjs.org/%40scope%2Fdemo", 30)]


def test_clean_process_faiss_builder_writes_compatible_index(tmp_path):
    vectors = np.array([[1.0, 0.0], [0.0, 1.0]], dtype=np.float32)
    source = tmp_path / "vectors.npy"
    output = tmp_path / "index.faiss"
    np.save(source, vectors)

    subprocess.run(
        [sys.executable, "-m", "cli.faiss_builder", str(source), str(output)],
        check=True, capture_output=True,
    )

    index = load_faiss_index(output)
    similarities, ids = index.search(vectors[:1], 1)
    assert index.ntotal == 2
    assert ids.tolist() == [[0]]
    assert similarities[0, 0] == pytest.approx(1.0)
