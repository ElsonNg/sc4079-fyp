import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import numpy as np

from corpus.models.corpus import CorpusEntry
from pipeline.integrations import embedding, vector_index
from pipeline.integrations.embedding import DEFAULT_MODEL_ID
from pipeline.controller.parsing import normalize_source
from pipeline.models.retrieval import RetrievalMatch

DEFAULT_EMBEDDINGS_DIR = Path(__file__).resolve().parent.parent.parent / "corpus" / "data" / "embeddings"

DEFAULT_EF_CONSTRUCTION = 200
DEFAULT_EF_SEARCH = 256
DEFAULT_HNSW_M = 32
INDEX_FORMAT_VERSION = 2
WINDOW_CHARS = 256
WINDOW_STRIDE_CHARS = 192
MAX_CORPUS_WINDOWS = 8
MAX_QUERY_WINDOWS = 32


@dataclass
class RetrievalIndex:
    model_id: str
    index: "faiss.Index"
    entries: list[RetrievalMatch] = field(default_factory=list)


def _normalized_text(source: str) -> str:
    return " ".join(normalize_source(source))


def _corpus_fingerprint(entries: list[CorpusEntry]) -> str:
    keys = sorted(
        f"{e.advisory.ghsa_id}|{e.advisory.advisory_title}|{e.origin.fix_commit_sha}|{e.origin.file_path}|{e.origin.function_name}|"
        f"{hashlib.sha256(e.vulnerable_function.encode('utf-8')).hexdigest()}"
        for e in entries
    )
    settings = (
        f"format={INDEX_FORMAT_VERSION}|window={WINDOW_CHARS}|stride={WINDOW_STRIDE_CHARS}|"
        f"corpus_windows={MAX_CORPUS_WINDOWS}"
    )
    return hashlib.sha256((settings + "\n" + "\n".join(keys)).encode("utf-8")).hexdigest()


def _select_evenly(values: list[int], limit: int) -> list[int]:
    values = sorted(set(values))
    if len(values) <= limit:
        return values
    if limit == 1:
        return [values[len(values) // 2]]
    indexes = [round(i * (len(values) - 1) / (limit - 1)) for i in range(limit)]
    return [values[index] for index in indexes]


def _window_at(source: str, start: int) -> str:
    start = max(0, min(start, max(0, len(source) - WINDOW_CHARS)))
    return source[start : start + WINDOW_CHARS]


def _query_windows(source: str) -> list[str]:
    if len(source) <= WINDOW_CHARS:
        return [source]
    starts = list(range(0, max(1, len(source) - WINDOW_CHARS + 1), WINDOW_STRIDE_CHARS))
    starts.append(len(source) - WINDOW_CHARS)
    return [_window_at(source, start) for start in _select_evenly(starts, MAX_QUERY_WINDOWS)]


def _corpus_windows(entry: CorpusEntry) -> list[str]:
    """Represent a vulnerable function around the lines the security fix touched.

    Prefix/suffix coverage remains available, while diagnostic anchors ensure the
    vulnerable mechanism is represented even when it occurs deep in generated code.
    """
    source = entry.vulnerable_function
    if len(source) <= WINDOW_CHARS:
        return [source]
    offsets = []
    cursor = 0
    for line in source.splitlines(keepends=True):
        offsets.append(cursor)
        cursor += len(line)
    starts = [0, len(source) - WINDOW_CHARS]
    for diagnostic in entry.diagnostic_lines:
        line = diagnostic.vulnerable_line
        if line is not None and line < len(offsets):
            starts.append(offsets[line] - WINDOW_CHARS // 2)
    starts = [max(0, min(start, len(source) - WINDOW_CHARS)) for start in starts]
    return [_window_at(source, start) for start in _select_evenly(starts, MAX_CORPUS_WINDOWS)]


def _match_from_entry(entry: CorpusEntry) -> RetrievalMatch:
    return RetrievalMatch(
        advisory=entry.advisory,
        origin=entry.origin,
    )


def build_faiss_index(
    corpus_entries: list[CorpusEntry],
    model_id: str = DEFAULT_MODEL_ID,
    ef_construction: int = DEFAULT_EF_CONSTRUCTION,
    ef_search: int = DEFAULT_EF_SEARCH,
    m: int = DEFAULT_HNSW_M,
    embedding_batch_size: int = embedding.DEFAULT_EMBEDDING_BATCH_SIZE,
    progress_callback: Callable[[int, int], None] | None = None,
) -> RetrievalIndex:
    """Builds a FAISS IndexHNSWFlat over the corpus's vulnerable_function entries.
    Vectors are L2-normalized (embedding.encode's default) and the index uses inner
    product, so search scores are directly cosine similarity. `ef_search` defaults high
    -- tuned for recall over speed, since a missed match here is a false negative on a
    real vulnerability, not a minor UX gap."""
    normalized_texts: list[str] = []
    vector_entries: list[RetrievalMatch] = []
    for entry in corpus_entries:
        windows = _corpus_windows(entry)
        normalized_texts.extend(_normalized_text(window) for window in windows)
        vector_entries.extend(_match_from_entry(entry) for _ in windows)
    encode_kwargs = {"batch_size": embedding_batch_size}
    if progress_callback is not None:
        encode_kwargs["progress_callback"] = progress_callback
    vectors = embedding.encode(model_id, normalized_texts, **encode_kwargs)
    del normalized_texts
    embedding.release_models()

    dim = vectors.shape[1] if vectors.size else embedding.get_model(model_id).get_embedding_dimension()
    index = vector_index.build_hnsw_index(vectors, dim, m, ef_construction, ef_search)

    return RetrievalIndex(
        model_id=model_id,
        index=index,
        entries=vector_entries,
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

    vector_index.save_faiss_index(retrieval_index.index, index_path)
    meta = {
        "index_format_version": INDEX_FORMAT_VERSION,
        "model_id": retrieval_index.model_id,
        "corpus_fingerprint": _corpus_fingerprint(corpus_entries),
        "entries": [e.model_dump() for e in retrieval_index.entries],
    }
    vector_index.write_index_metadata(meta_path, meta)


def load_index(
    model_id: str = DEFAULT_MODEL_ID,
    dir_path: Path = DEFAULT_EMBEDDINGS_DIR,
) -> RetrievalIndex | None:
    index_path, meta_path = _index_paths(model_id, dir_path)
    if not index_path.exists() or not meta_path.exists():
        return None

    index = vector_index.load_faiss_index(index_path)
    meta = vector_index.read_index_metadata(meta_path)
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
    meta = vector_index.read_index_metadata(meta_path)
    return (
        meta.get("index_format_version") != INDEX_FORMAT_VERSION
        or meta.get("corpus_fingerprint") != _corpus_fingerprint(corpus_entries)
    )


def build_or_load_index(
    corpus_entries: list[CorpusEntry],
    model_id: str = DEFAULT_MODEL_ID,
    dir_path: Path = DEFAULT_EMBEDDINGS_DIR,
    ef_construction: int = DEFAULT_EF_CONSTRUCTION,
    ef_search: int = DEFAULT_EF_SEARCH,
    m: int = DEFAULT_HNSW_M,
    embedding_batch_size: int = embedding.DEFAULT_EMBEDDING_BATCH_SIZE,
    progress_callback: Callable[[int, int], None] | None = None,
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
        embedding_batch_size=embedding_batch_size,
        progress_callback=progress_callback,
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

    normalized_texts: list[str] = []
    owners: list[int] = []
    for owner, source in enumerate(target_sources):
        windows = _query_windows(source)
        normalized_texts.extend(_normalized_text(window) for window in windows)
        owners.extend([owner] * len(windows))
    vectors = embedding.encode(retrieval_index.model_id, normalized_texts)

    search_k = min(max(k, k * MAX_CORPUS_WINDOWS), len(retrieval_index.entries))
    similarities, ids = vector_index.search_index(retrieval_index.index, vectors, search_k)

    aggregated: list[dict[tuple[str, str, str, str | None], RetrievalMatch]] = [
        {} for _ in target_sources
    ]
    for owner, row_sims, row_ids in zip(owners, similarities, ids):
        for sim, idx in zip(row_sims, row_ids):
            if idx < 0 or sim < threshold:
                continue
            base = retrieval_index.entries[idx]
            key = (base.advisory.ghsa_id, base.origin.fix_commit_sha, base.origin.file_path, base.origin.function_name)
            previous = aggregated[owner].get(key)
            if previous is None or float(sim) > previous.similarity:
                aggregated[owner][key] = base.model_copy(update={"similarity": float(sim)})
    return [
        sorted(matches.values(), key=lambda match: match.similarity, reverse=True)[:k]
        for matches in aggregated
    ]


def query(
    target_source: str,
    retrieval_index: RetrievalIndex,
    k: int = 5,
    threshold: float = 0.7,
) -> list[RetrievalMatch]:
    return query_batch([target_source], retrieval_index, k=k, threshold=threshold)[0]
