"""Clean-process FAISS builder used to isolate FAISS from PyTorch runtimes."""

import argparse
from pathlib import Path

import numpy as np

from provtrail.pipeline.integrations.vector_index import build_hnsw_index, save_faiss_index


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("vectors")
    parser.add_argument("output")
    parser.add_argument("--m", type=int, default=32)
    parser.add_argument("--ef-construction", type=int, default=200)
    parser.add_argument("--ef-search", type=int, default=256)
    args = parser.parse_args()
    vectors = np.load(args.vectors)
    index = build_hnsw_index(
        vectors, vectors.shape[1], args.m, args.ef_construction, args.ef_search,
    )
    save_faiss_index(index, Path(args.output))


if __name__ == "__main__":
    main()
