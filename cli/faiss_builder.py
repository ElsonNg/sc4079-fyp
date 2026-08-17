"""Clean-process FAISS builder used to isolate FAISS from PyTorch runtimes."""

import argparse

import faiss
import numpy as np


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("vectors")
    parser.add_argument("output")
    parser.add_argument("--m", type=int, default=32)
    parser.add_argument("--ef-construction", type=int, default=200)
    parser.add_argument("--ef-search", type=int, default=256)
    args = parser.parse_args()
    vectors = np.load(args.vectors)
    index = faiss.IndexHNSWFlat(vectors.shape[1], args.m, faiss.METRIC_INNER_PRODUCT)
    index.hnsw.efConstruction = args.ef_construction
    index.hnsw.efSearch = args.ef_search
    index.add(vectors)
    faiss.write_index(index, args.output)


if __name__ == "__main__":
    main()
