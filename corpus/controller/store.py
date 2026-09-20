"""Compatibility imports for the SQLite corpus repository."""

from corpus.integrations.sqlite_store import (
    DEFAULT_DB_PATH, SCHEMA, get_connection, load_entries,
    replace_entries_by_ghsa_prefix, save_entries,
)
