"""Compatibility imports for the embedding model adapter."""

from pipeline.integrations.embedding import (
    DEFAULT_EMBEDDING_BATCH_SIZE, DEFAULT_MAX_SEQ_LENGTH, EMBEDDING_DEVICE_ENV,
    MAX_EMBEDDING_INPUT_CHARS, MODEL_REGISTRY, DEFAULT_MODEL_ID,
    encode, get_model, release_models,
)
