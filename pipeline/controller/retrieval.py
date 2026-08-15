import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

import faiss
import numpy as np

from corpus.models.corpus import CorpusEntry
from pipeline.controller import embedding
from pipeline.controller.embedding import DEFAULT_MODEL_ID
from pipeline.controller.parsing import normalize_source
from pipeline.models.retrieval import RetrievalMatch

DEFAULT_EMBEDDINGS_DIR = Path(__file__).resolve().parent.parent.parent / "corpus" / "data" / "embeddings"

DEFAULT_EF_CONSTRUCTION = 200
DEFAULT_EF_SEARCH = 256
DEFAULT_HNSW_M = 32


@dataclass
class RetrievalIndex:
    model_id: str
    index: "faiss.Index"
    entries: list[RetrievalMatch] = field(default_factory=list)


def _normalized_text(source: str) -> str:
    return " ".join(normalize_source(source))


def _corpus_fingerprint(entries: list[CorpusEntry]) -> str:
    keys = sorted(
        f"{e.ghsa_id}|{e.fix_commit_sha}|{e.file_path}|{e.function_name}"
        for e in entries
    )
    return hashlib.sha256("\n".join(keys).encode("utf-8")).hexdigest()


def _match_from_entry(entry: CorpusEntry) -> RetrievalMatch:
    return RetrievalMatch(
        ghsa_id=entry.ghsa_id,
        cve_id=entry.cve_id,
        cwes=entry.cwes,
        severity=entry.severity,
        repo=entry.repo,
        fix_commit_sha=entry.fix_commit_sha,
        file_path=entry.file_path,
        function_name=entry.function_name,
    )


def build_faiss_index(
    corpus_entries: list[CorpusEntry],
    model_id: str = DEFAULT_MODEL_ID,
    ef_construction: int = DEFAULT_EF_CONSTRUCTION,
    ef_search: int = DEFAULT_EF_SEARCH,
    m: int = DEFAULT_HNSW_M,
) -> RetrievalIndex:
    """Builds a FAISS IndexHNSWFlat over the corpus's vulnerable_function entries.
    Vectors are L2-normalized (embedding.encode's default) and the index uses inner
    product, so search scores are directly cosine similarity. `ef_search` defaults high
    -- tuned for recall over speed, since a missed match here is a false negative on a
    real vulnerability, not a minor UX gap."""
    normalized_texts = [_normalized_text(e.vulnerable_function) for e in corpus_entries]
    vectors = embedding.encode(model_id, normalized_texts)

    dim = vectors.shape[1] if vectors.size else embedding.get_model(model_id).get_embedding_dimension()
    index = faiss.IndexHNSWFlat(dim, m, faiss.METRIC_INNER_PRODUCT)
    index.hnsw.efConstruction = ef_construction
    index.hnsw.efSearch = ef_search
    if vectors.size:
        index.add(vectors)

    return RetrievalIndex(
        model_id=model_id,
        index=index,
        entries=[_match_from_entry(e) for e in corpus_entries],
    )


def _index_paths(model_id: str, dir_path: Path) -> tuple[Path, Path]:
    return dir_path / f"{model_id}.faiss", dir_path / f"{model_id}.meta.json"


def save_index(
    retrieval_index: RetrievalIndex,
    corpus_entries: list[CorpusEntry],
    dir_path: Path = DEFAULT_EMBEDDINGS_DIR,
) -> None:
    dir_path.mkdir(parents=True, exist_ok=True)
    index_path, meta_path = _index_paths(retrieval_index.model_id, dir_path)

    faiss.write_index(retrieval_index.index, str(index_path))
    meta = {
        "model_id": retrieval_index.model_id,
        "corpus_fingerprint": _corpus_fingerprint(corpus_entries),
        "entries": [e.model_dump() for e in retrieval_index.entries],
    }
    meta_path.write_text(json.dumps(meta))


def load_index(
    model_id: str = DEFAULT_MODEL_ID,
    dir_path: Path = DEFAULT_EMBEDDINGS_DIR,
) -> RetrievalIndex | None:
    index_path, meta_path = _index_paths(model_id, dir_path)
    if not index_path.exists() or not meta_path.exists():
        return None

    index = faiss.read_index(str(index_path))
    meta = json.loads(meta_path.read_text())
    return RetrievalIndex(
        model_id=meta["model_id"],
        index=index,
        entries=[RetrievalMatch(**e) for e in meta["entries"]],
    )


def is_stale(
    model_id: str,
    corpus_entries: list[CorpusEntry],
    dir_path: Path = DEFAULT_EMBEDDINGS_DIR,
) -> bool:
    _, meta_path = _index_paths(model_id, dir_path)
    if not meta_path.exists():
        return True
    meta = json.loads(meta_path.read_text())
    return meta.get("corpus_fingerprint") != _corpus_fingerprint(corpus_entries)


def build_or_load_index(
    corpus_entries: list[CorpusEntry],
    model_id: str = DEFAULT_MODEL_ID,
    dir_path: Path = DEFAULT_EMBEDDINGS_DIR,
    ef_construction: int = DEFAULT_EF_CONSTRUCTION,
    ef_search: int = DEFAULT_EF_SEARCH,
    m: int = DEFAULT_HNSW_M,
) -> RetrievalIndex:
    if not is_stale(model_id, corpus_entries, dir_path):
        loaded = load_index(model_id, dir_path)
        if loaded is not None:
            return loaded

    retrieval_index = build_faiss_index(
        corpus_entries,
        model_id=model_id,
        ef_construction=ef_construction,
        ef_search=ef_search,
        m=m,
    )
    save_index(retrieval_index, corpus_entries, dir_path)
    return retrieval_index


def query_batch(
    target_sources: list[str],
    retrieval_index: RetrievalIndex,
    k: int = 5,
    threshold: float = 0.7,
) -> list[list[RetrievalMatch]]:
    """Batch-embeds every target function in one call, then does one FAISS search call
    for all of them -- the batching required for scanning a target codebase's functions
    in groups, not one at a time."""
    if not target_sources or not retrieval_index.entries:
        return [[] for _ in target_sources]

    normalized_texts = [_normalized_text(s) for s in target_sources]
    vectors = embedding.encode(retrieval_index.model_id, normalized_texts)

    k = min(k, len(retrieval_index.entries))
    similarities, ids = retrieval_index.index.search(vectors, k)

    results: list[list[RetrievalMatch]] = []
    for row_sims, row_ids in zip(similarities, ids):
        matches = []
        for sim, idx in zip(row_sims, row_ids):
            if idx < 0 or sim < threshold:
                continue
            base = retrieval_index.entries[idx]
            matches.append(base.model_copy(update={"similarity": float(sim)}))
        matches.sort(key=lambda m: m.similarity, reverse=True)
        results.append(matches)
    return results


def query(
    target_source: str,
    retrieval_index: RetrievalIndex,
    k: int = 5,
    threshold: float = 0.7,
) -> list[RetrievalMatch]:
    return query_batch([target_source], retrieval_index, k=k, threshold=threshold)[0]
