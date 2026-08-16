import numpy as np

from pipeline.controller import embedding


class _BufferLimitedModel:
    device = "cpu"

    def __init__(self) -> None:
        self.attempted_batch_sizes: list[int] = []

    def encode(self, texts, *, batch_size, **_kwargs):
        self.attempted_batch_sizes.append(batch_size)
        if batch_size > 1:
            raise RuntimeError("Invalid buffer size: 8.00 GB")
        return np.zeros((len(texts), 3), dtype=np.float32)


def test_default_embedding_batch_size_is_memory_conservative():
    assert embedding.DEFAULT_EMBEDDING_BATCH_SIZE == 4
    assert embedding.encode.__defaults__ == (embedding.DEFAULT_EMBEDDING_BATCH_SIZE,)


def test_invalid_buffer_size_triggers_batch_backoff(monkeypatch):
    model = _BufferLimitedModel()
    monkeypatch.setattr(embedding, "_clear_device_cache", lambda _model: None)

    vectors = embedding._encode_chunk(model, ["a", "b", "c", "d"], 4)

    assert model.attempted_batch_sizes == [4, 2, 1]
    assert vectors.shape == (4, 3)


def test_unrelated_runtime_error_is_not_treated_as_memory_pressure():
    assert not embedding._is_oom_error(RuntimeError("model configuration is invalid"))
