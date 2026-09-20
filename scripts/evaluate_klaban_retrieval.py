"""Compatibility entry point for eval.tier1.evaluate_klaban_retrieval."""

import sys
from importlib import import_module
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_module = import_module("eval.tier1.evaluate_klaban_retrieval")

def __getattr__(name):
    return getattr(_module, name)

if __name__ == "__main__":
    _module.main()
