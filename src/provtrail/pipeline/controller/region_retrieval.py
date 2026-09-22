"""Semantic retrieval over vulnerable AST regions."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import numpy as np

from provtrail.pipeline.integrations import embedding, vector_index
from provtrail.pipeline.detection.config import DEFAULT_MODEL_ID, DEFAULT_REGION_THRESHOLD, DEFAULT_REGION_TOP_K
from provtrail.pipeline.models.boundary import VulnerableRegionPair
from provtrail.pipeline.models.region import CandidateRegion
from provtrail.pipeline.models.region_retrieval import RegionRetrievalMatch
from provtrail.paths import data_dir

DEFAULT_REGION_EMBEDDINGS_DIR = data_dir() / "region_embeddings"


@dataclass
class RegionRetrievalIndex:
    model_id: str
    index: "faiss.Index"
    pairs: list[VulnerableRegionPair] = field(default_factory=list)
    indexed_pair_ids: list[str] = field(default_factory=list)
    indexed_sides: list[str] = field(default_factory=list)
    fingerprint: str = ""


def _region_fingerprint(pairs: list[VulnerableRegionPair], model_id: str) -> str:
    values = [
        f"symmetric-v3-fp32|{model_id}|{pair.pair_id}|{pair.lineage_id}|{pair.advisory.advisory_title}|"
        f"{json.dumps([item.model_dump() for item in pair.advisories], sort_keys=True)}|"
        f"{pair.change.vulnerable_source_sha256}|{pair.change.patched_source_sha256}|"
        f"{pair.vulnerable_region.source}|{pair.patched_region.source}"
        for pair in pairs
    ]
    return hashlib.sha256("\n".join(sorted(values)).encode("utf-8")).hexdigest()


def build_region_index(
    pairs: list[VulnerableRegionPair],
    model_id: str = DEFAULT_MODEL_ID,
    ef_construction: int = 200,
    ef_search: int = 256,
    m: int = 32,
    progress_callback: Callable[[int, int], None] | None = None,
) -> RegionRetrievalIndex:
    texts = [
        region.embedding_text
        for pair in pairs
        for region in (pair.vulnerable_region, pair.patched_region)
    ]
    # Keep first-time corpus indexing observable and avoid one long silent model call.
    vectors_parts = []
    index_batch_size = 32
    for start in range(0, len(texts), index_batch_size):
        vectors_parts.append(embedding.encode(model_id, texts[start : start + index_batch_size]))
        if progress_callback is not None:
            progress_callback(min(start + index_batch_size, len(texts)), len(texts))
    vectors = (
        np.concatenate(vectors_parts, axis=0)
        if vectors_parts
        else np.empty((0, 0), dtype=np.float32)
    )
    if vectors.size:
        dimension = vectors.shape[1]
    else:
        dimension = embedding.get_model(model_id).get_embedding_dimension()
    embedding.release_models()
    index = vector_index.build_hnsw_index(vectors, dimension, m, ef_construction, ef_search)
    return RegionRetrievalIndex(
        model_id=model_id,
        index=index,
        pairs=pairs,
        indexed_pair_ids=[pair.pair_id for pair in pairs for _ in range(2)],
        indexed_sides=[side for _pair in pairs for side in ("vulnerable", "patched")],
        fingerprint=_region_fingerprint(pairs, model_id),
    )


def query_region_batch(
    candidate_regions: list[CandidateRegion],
    retrieval_index: RegionRetrievalIndex,
    top_k: int = DEFAULT_REGION_TOP_K,
    threshold: float = DEFAULT_REGION_THRESHOLD,
) -> list[list[RegionRetrievalMatch]]:
    if not candidate_regions or not retrieval_index.pairs:
        return [[] for _ in candidate_regions]
    texts = [candidate.region.embedding_text for candidate in candidate_regions]
    vectors = embedding.encode(retrieval_index.model_id, texts)
    indexed_count = len(retrieval_index.indexed_pair_ids) or len(retrieval_index.pairs)
    k = min(top_k, indexed_count)
    # HNSW can choose different members of a tied neighbourhood when FAISS is
    # asked to search a matrix in parallel. Keep model encoding batched (the
    # expensive part), but search each region vector independently so batching
    # does not change the established sequential shortlist semantics.
    searched = vector_index.search_each(retrieval_index.index, vectors, k)
    results: list[list[RegionRetrievalMatch]] = []
    for candidate, (row_sims, row_ids) in zip(candidate_regions, searched):
        row_sims = row_sims[0]
        row_ids = row_ids[0]
        matches: list[RegionRetrievalMatch] = []
        for rank, (similarity, index_id) in enumerate(zip(row_sims, row_ids), start=1):
            if index_id < 0 or float(similarity) < threshold:
                continue
            if retrieval_index.indexed_pair_ids:
                pairs_by_id = {pair.pair_id: pair for pair in retrieval_index.pairs}
                pair = pairs_by_id[retrieval_index.indexed_pair_ids[int(index_id)]]
                reference_side = retrieval_index.indexed_sides[int(index_id)]
            else:
                pair = retrieval_index.pairs[int(index_id)]
                reference_side = "vulnerable"
            matches.append(
                RegionRetrievalMatch(
                    pair_id=pair.pair_id,
                    lineage_id=pair.lineage_id,
                    fix_boundary_id=pair.fix_boundary_id,
                    reference_side=reference_side,
                    advisories=pair.advisories,
                    similarity=float(similarity),
                    rank=rank,
                    candidate_region_id=candidate.region.region_id,
                    candidate_granularity=candidate.region.granularity,
                    corpus_granularity=pair.vulnerable_region.granularity,
                    advisory=pair.advisory,
                    origin=pair.origin,
                )
            )
        results.append(matches)
    return results


def query_regions(
    candidate_regions: list[CandidateRegion],
    retrieval_index: RegionRetrievalIndex,
    top_k: int = DEFAULT_REGION_TOP_K,
    threshold: float = DEFAULT_REGION_THRESHOLD,
) -> list[RegionRetrievalMatch]:
    return [
        match
        for batch in query_region_batch(candidate_regions, retrieval_index, top_k, threshold)
        for match in batch
    ]


def aggregate_region_hits(matches: list[RegionRetrievalMatch]) -> list[tuple[str, list[RegionRetrievalMatch]]]:
    grouped: dict[str, list[RegionRetrievalMatch]] = {}
    for match in matches:
        grouped.setdefault(match.pair_id, []).append(match)
    return sorted(
        grouped.items(),
        key=lambda item: (
            -max(match.similarity for match in item[1]),
            -len(item[1]),
            item[0],
        ),
    )


def save_region_index(
    retrieval_index: RegionRetrievalIndex,
    directory: Path = DEFAULT_REGION_EMBEDDINGS_DIR,
) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    stem = retrieval_index.model_id
    vector_index.save_faiss_index(retrieval_index.index, directory / f"{stem}.faiss")
    metadata = {
        "model_id": retrieval_index.model_id,
        "fingerprint": retrieval_index.fingerprint,
        "pairs": [pair.to_record() for pair in retrieval_index.pairs],
        "indexed_pair_ids": retrieval_index.indexed_pair_ids,
        "indexed_sides": retrieval_index.indexed_sides,
    }
    vector_index.write_index_metadata(directory / f"{stem}.meta.json", metadata)


def load_region_index(
    pairs: list[VulnerableRegionPair],
    model_id: str = DEFAULT_MODEL_ID,
    directory: Path = DEFAULT_REGION_EMBEDDINGS_DIR,
) -> RegionRetrievalIndex | None:
    index_path = directory / f"{model_id}.faiss"
    metadata_path = directory / f"{model_id}.meta.json"
    if not index_path.exists() or not metadata_path.exists():
        return None
    metadata = vector_index.read_index_metadata(metadata_path)
    expected = _region_fingerprint(pairs, model_id)
    if metadata.get("fingerprint") != expected:
        return None
    return RegionRetrievalIndex(
        model_id=model_id,
        index=vector_index.load_faiss_index(index_path),
        pairs=pairs,
        indexed_pair_ids=list(metadata.get("indexed_pair_ids", [])),
        indexed_sides=list(metadata.get("indexed_sides", [])),
        fingerprint=expected,
    )
