"""Compatibility entry point for eval.fixtures.generate_candidate_subset."""

import sys
from importlib import import_module
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_module = import_module("eval.fixtures.generate_candidate_subset")

def __getattr__(name):
    return getattr(_module, name)

if __name__ == "__main__":
    _module.main()
