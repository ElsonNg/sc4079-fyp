import threading
from typing import TYPE_CHECKING

import numpy as np

from pipeline.models.embedding import ModelSpec

if TYPE_CHECKING:
    from sentence_transformers import SentenceTransformer

MODEL_REGISTRY: dict[str, ModelSpec] = {
    "qwen3-embedding-0.6b": ModelSpec(
        model_id="qwen3-embedding-0.6b",
        hf_name="Qwen/Qwen3-Embedding-0.6B",
        label="Qwen3-Embedding-0.6B",
    ),
    "embeddinggemma-300m": ModelSpec(
        model_id="embeddinggemma-300m",
        hf_name="google/embeddinggemma-300m",
        label="EmbeddingGemma-300M",
    ),
}

DEFAULT_MODEL_ID = "qwen3-embedding-0.6b"

# Qwen3-Embedding-0.6B's own default max_seq_length is 32768 tokens -- appropriate for
# a general-purpose embedding model, not for this pipeline. A handful of real corpus
# functions run to 15k+ characters (~4-5k tokens); left uncapped, a batch containing
# them makes attention's O(n^2) cost explode (observed: multi-minute hangs / MPS OOM
# for a single such batch). Retrieval doesn't need the full body anyway -- the opening
# of a function carries most of the signature/intent signal. Capping trades a small
# amount of tail-end signal on rare huge functions for the pipeline actually completing.
DEFAULT_MAX_SEQ_LENGTH = 512

_loaded_models: dict[str, "SentenceTransformer"] = {}

# PyTorch's MPS (Apple GPU) backend is not safe to call concurrently from multiple
# threads -- two local models running .encode() at the exact same instant on separate
# threads reliably crashes the process. Model loading is fine concurrently; only the
# actual local compute step needs to be serialized.
_encode_lock = threading.Lock()


def get_model(model_id: str) -> "SentenceTransformer":
    spec = MODEL_REGISTRY.get(model_id)
    if spec is None:
        raise ValueError(f"Unknown model id: {model_id}")
    if model_id not in _loaded_models:
        from sentence_transformers import SentenceTransformer

        model = SentenceTransformer(spec.hf_name)
        model.max_seq_length = DEFAULT_MAX_SEQ_LENGTH
        _loaded_models[model_id] = model
    return _loaded_models[model_id]


def _is_oom_error(exc: RuntimeError) -> bool:
    message = str(exc).lower()
    return "out of memory" in message or "outofmemory" in message


def _clear_device_cache(model: "SentenceTransformer") -> None:
    """OOM retries only help if the failed attempt's memory is actually released first
    -- PyTorch's MPS/CUDA caching allocators hold onto freed blocks for reuse rather
    than returning them to the OS, so a bare retry at a smaller batch size can still
    fail against memory the previous attempt never gave back."""
    import torch

    device = str(model.device)
    if device.startswith("mps") and torch.backends.mps.is_available():
        torch.mps.empty_cache()
    elif device.startswith("cuda") and torch.cuda.is_available():
        torch.cuda.empty_cache()


def _encode_chunk(model: "SentenceTransformer", chunk: list[str], batch_size: int) -> np.ndarray:
    """Encodes one chunk, halving batch_size and clearing the device cache on OOM
    until it fits (down to a single item)."""
    current_batch_size = min(batch_size, len(chunk))
    while True:
        try:
            with _encode_lock:
                return model.encode(
                    chunk,
                    batch_size=current_batch_size,
                    convert_to_numpy=True,
                    normalize_embeddings=True,
                    show_progress_bar=False,
                )
        except RuntimeError as exc:
            if current_batch_size <= 1 or not _is_oom_error(exc):
                raise
            _clear_device_cache(model)
            current_batch_size = max(1, current_batch_size // 2)


def encode(model_id: str, texts: list[str], batch_size: int = 32) -> np.ndarray:
    """Batch-encode `texts` with `model_id`, returning L2-normalized float32 vectors
    (so downstream FAISS inner-product search is equivalent to cosine similarity).

    Corpus/target function sources vary wildly in length (a few lines to 15k+
    characters) -- a batch containing several long outliers can blow past MPS's memory
    limit even though `batch_size` looks conservative, since every item in a batch is
    padded to the longest one. Texts are sorted by length and walked in `batch_size`
    chunks (each chunk own OOM retry, not the whole call) so a single expensive chunk
    doesn't force re-encoding everything else that already succeeded."""
    if not texts:
        model = get_model(model_id)
        return np.empty((0, model.get_embedding_dimension()), dtype=np.float32)

    model = get_model(model_id)
    order = sorted(range(len(texts)), key=lambda i: len(texts[i]), reverse=True)
    sorted_texts = [texts[i] for i in order]

    dim = model.get_embedding_dimension()
    result = np.empty((len(texts), dim), dtype=np.float32)

    pos = 0
    while pos < len(sorted_texts):
        chunk = sorted_texts[pos : pos + batch_size]
        vectors = _encode_chunk(model, chunk, batch_size)
        for offset, vector in enumerate(vectors):
            result[order[pos + offset]] = vector
        pos += len(chunk)

    return result
