"""Compatibility imports for incremental scan state."""

from pipeline.scanning.cache import (
    DEFAULT_EXCLUDED_DIRS, DEFAULT_STATE_FILENAME, STATE_SCHEMA_VERSION,
    MerkleSnapshot, ScanState, build_merkle_snapshot, changed_paths,
    fingerprint_config, load_scan_state, save_scan_state,
)
