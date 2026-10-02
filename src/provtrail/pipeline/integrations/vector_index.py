"""FAISS index construction, search and binary persistence."""

import json
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import faiss
import numpy as np


def build_hnsw_index(
    vectors: np.ndarray, dimension: int, m: int,
    ef_construction: int, ef_search: int,
) -> Any:
    index = faiss.IndexHNSWFlat(dimension, m, faiss.METRIC_INNER_PRODUCT)
    index.hnsw.efConstruction = ef_construction
    index.hnsw.efSearch = ef_search
    if vectors.size:
        index.add(vectors)
    return index


def build_hnsw_index_isolated(
    vectors: np.ndarray, dimension: int, m: int,
    ef_construction: int, ef_search: int,
) -> Any:
    """Build in a clean process to isolate FAISS from embedding runtimes."""
    with TemporaryDirectory(prefix="provtrail-index-") as temporary:
        directory = Path(temporary)
        source = directory / "vectors.npy"
        output = directory / "index.faiss"
        np.save(source, vectors.reshape(-1, dimension))
        subprocess.run([
            sys.executable, "-m", "provtrail.cli.faiss_builder", str(source), str(output),
            "--m", str(m), "--ef-construction", str(ef_construction),
            "--ef-search", str(ef_search),
        ], check=True)
        return load_faiss_index(output)


def search_each(index: Any, vectors: np.ndarray, k: int):
    # Region retrieval searches separately to preserve tied-neighbor ordering.
    return [index.search(vector[None, :], k) for vector in vectors]


def save_faiss_index(index: Any, path: Path) -> None:
    faiss.write_index(index, str(path))


def load_faiss_index(path: Path) -> Any:
    return faiss.read_index(str(path))


def write_index_metadata(path: Path, metadata: dict) -> None:
    path.write_text(json.dumps(metadata), encoding="utf-8")


def read_index_metadata(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))
