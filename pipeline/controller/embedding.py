import gc
import os
import threading
from typing import TYPE_CHECKING, Callable

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
# for a single such batch). 512 was the original cap, but it truncates to roughly the
# first ~2000 characters -- multiple real corpus revisions of the same large function
# (e.g. axios's ~18-24k char dispatchHttpRequest, revised across 15 separate advisories)
# share an identical opening at that length and become indistinguishable embeddings, a
# false-negative risk for exactly the functions this stage most needs to discriminate.
# 64 keeps full-corpus CPU indexing tractable; encode()'s chunk-level OOM backoff (halving
# batch size down to 1 item) exists specifically to absorb the rare huge-outlier cost
# this raises, rather than avoiding it by truncating harder.
#
# Known residual limitation (accepted, not fixed): 64 tokens covers only a function prefix and is
# short of dispatchHttpRequest's 18-24k characters, so some of its 15 corpus revisions
# still tie on identical similarity to each other. Verified via smoke test against the
# real corpus -- doesn't cause a false negative (the correct entry is still retrieved,
# just tied with siblings), so Stage 2's shortlist still includes it; Stage 3's per-line
# alignment (no token cap there) is what actually disambiguates which specific revision
# matched. A true fix would need windowed/chunked embedding for over-cap functions
# (embed multiple <=2048-token windows, combine via mean-pool or max-similarity-at-query)
# to get full-body coverage without paying attention's O(n^2) cost on the whole body at
# once -- not implemented; revisit if Stage 2 recall on large functions proves to be a
# problem in the eval suite (module 11). Klaban also contains generated functions up to
# ~800 KB, making longer full-corpus CPU inference impractical in the supported local
# environment. Windowed embeddings remain the proper future solution for those outliers.
DEFAULT_MAX_SEQ_LENGTH = 64
DEFAULT_EMBEDDING_BATCH_SIZE = 4
# Hugging Face truncates to DEFAULT_MAX_SEQ_LENGTH tokens, but its native tokenizer
# still has to scan the complete input first. Klaban includes generated/minified
# functions approaching 800 KB; after whitespace normalization, a 605 KB single line
# can segfault the tokenizer before token truncation runs. Typical JavaScript reaches
# 2,048 tokens within roughly 8 KB, so this cap leaves a generous buffer while
# keeping pathological inputs out of native code.
MAX_EMBEDDING_INPUT_CHARS = 16 * 1024
EMBEDDING_DEVICE_ENV = "PROVTRAIL_EMBEDDING_DEVICE"

# PyTorch and faiss-cpu can bring separate OpenMP runtimes into the same macOS
# process. Without this compatibility setting the second native import can segfault.
os.environ.setdefault("KMP_DUPLICATE_LIB_OK", "TRUE")

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

        configured_device = os.environ.get(EMBEDDING_DEVICE_ENV)
        model = SentenceTransformer(spec.hf_name, device=configured_device)
        model.max_seq_length = DEFAULT_MAX_SEQ_LENGTH
        _loaded_models[model_id] = model
    return _loaded_models[model_id]


def release_models() -> None:
    """Release model weights before loading another large native runtime (FAISS)."""
    _loaded_models.clear()
    gc.collect()


def _is_oom_error(exc: RuntimeError) -> bool:
    message = str(exc).lower()
    return any(
        marker in message
        for marker in ("out of memory", "outofmemory", "invalid buffer size")
    )


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


def encode(
    model_id: str,
    texts: list[str],
    batch_size: int = DEFAULT_EMBEDDING_BATCH_SIZE,
    *,
    progress_callback: Callable[[int, int], None] | None = None,
) -> np.ndarray:
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
    prepared_texts = [text[:MAX_EMBEDDING_INPUT_CHARS] for text in texts]
    order = sorted(range(len(prepared_texts)), key=lambda i: len(prepared_texts[i]), reverse=True)
    sorted_texts = [prepared_texts[i] for i in order]

    dim = model.get_embedding_dimension()
    result = np.empty((len(texts), dim), dtype=np.float32)

    pos = 0
    while pos < len(sorted_texts):
        chunk = sorted_texts[pos : pos + batch_size]
        vectors = _encode_chunk(model, chunk, batch_size)
        for offset, vector in enumerate(vectors):
            result[order[pos + offset]] = vector
        pos += len(chunk)
        if progress_callback is not None:
            progress_callback(pos, len(texts))

    return result
