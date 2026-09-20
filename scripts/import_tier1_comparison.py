"""Compatibility entry point for eval.comparison_benchmark.import_tier1_comparison."""

import sys
from importlib import import_module
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_module = import_module("eval.comparison_benchmark.import_tier1_comparison")

def __getattr__(name):
    return getattr(_module, name)

if __name__ == "__main__":
    raise SystemExit(_module.main())
