"""Compatibility entry point for eval.fixtures.validate_worst_case."""

import argparse
import sys
from importlib import import_module
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_module = import_module("eval.fixtures.validate_worst_case")

def __getattr__(name):
    return getattr(_module, name)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["validate", "clone"], default="clone")
    args = parser.parse_args()
    _module.main(args.mode)
