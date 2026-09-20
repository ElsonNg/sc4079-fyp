"""Compatibility entry point for eval.ablation.run_decision_ablations."""

import sys
from importlib import import_module
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_module = import_module("eval.ablation.run_decision_ablations")

def __getattr__(name):
    return getattr(_module, name)

if __name__ == "__main__":
    _module.main()
