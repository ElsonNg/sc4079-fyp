"""Writable locations for corpus data and generated indexes."""

import os
from pathlib import Path


def data_dir() -> Path:
    configured = os.environ.get("PROVTRAIL_DATA_DIR")
    if configured:
        return Path(configured).expanduser()
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "ProvTrail"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "provtrail"
