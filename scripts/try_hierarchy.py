"""Ad hoc CLI for trying hierarchical alignment (Stage 3b) on your own JS functions.

Prints both the flat (Stage 3a) alignment and the hierarchical (Stage 3b) alignment
for two function sources, so you can see directly what decomposing along the AST buys
you over flattening the whole body into one line sequence -- e.g. a change that flat
alignment spans across a structural boundary (a for-loop's last line merged with the
line after it) instead gets correctly isolated to its real location once the AST is
taken into account.

Usage:
    # Compare two files, each containing one JS function:
    PYTHONPATH=. .venv/bin/python scripts/try_hierarchy.py path/to/a.js path/to/b.js

    # Pick a specific model (default: qwen3-embedding-0.6b):
    PYTHONPATH=. .venv/bin/python scripts/try_hierarchy.py a.js b.js --model embeddinggemma-300m

    # No args -- runs a small built-in demo pair (extract-variable split):
    PYTHONPATH=. .venv/bin/python scripts/try_hierarchy.py
"""
import argparse
import sys

from pipeline.controller import hierarchy
from pipeline.controller.alignment import align as flat_align
from pipeline.controller.embedding import DEFAULT_MODEL_ID, MODEL_REGISTRY
from pipeline.controller.hierarchy import EmbeddingCache, align_functions
from pipeline.controller.parsing import normalize_source

DEMO_A = """
function processOrders(orders) {
    let total = 0;
    for (let i = 0; i < orders.length; i++) {
        if (orders[i].valid) {
            total += orders[i].price * orders[i].quantity;
        } else {
            total += 0;
        }
    }
    return total;
}
"""

DEMO_B = """
function processOrders(orders) {
    let total = 0;
    for (let i = 0; i < orders.length; i++) {
        if (orders[i].valid) {
            total += orders[i].price * orders[i].quantity;
        } else {
            total += 0;
        }
    }
    const result = total;
    return result;
}
"""


# Heuristic-only thresholds for THIS script's summary line -- not module 7's
# verification_score (which build-plan module 7 defines as
# sim_at_diagnostic(candidate, vulnerable) - sim_at_diagnostic(candidate, patched),
# needs a vulnerable/patched corpus pair plus diagnostic lines, and isn't built yet).
# These just bucket the top-level normalized_score for eyeballing two arbitrary
# functions with this ad hoc tool.
_STRONG_MATCH_THRESHOLD = 0.3
_PARTIAL_MATCH_THRESHOLD = 0.0


def _verdict(normalized_score: float) -> str:
    if normalized_score >= _STRONG_MATCH_THRESHOLD:
        return "STRONG MATCH"
    if normalized_score >= _PARTIAL_MATCH_THRESHOLD:
        return "PARTIAL MATCH"
    return "NO MATCH"


def _print_summary(label: str, raw_score: float, normalized_score: float, scope: str) -> None:
    verdict = _verdict(normalized_score)
    print(
        f"\n{label} summary: raw_score={raw_score:+.4f}  normalized_score={normalized_score:+.4f}"
        f"  verdict={verdict}  (heuristic thresholds: >= {_STRONG_MATCH_THRESHOLD} strong, "
        f">= {_PARTIAL_MATCH_THRESHOLD} partial, else no-match -- not module 7's verification_score)"
    )
    print(f"  scope: {scope}")


_FLAT_SCOPE = "every line of the whole function, one flat comparison"
_HIERARCHICAL_SCOPE = (
    "the body's top-level statements ONLY -- deeper matches are never rolled up into "
    "this number by design (each level's score is its own sibling comparison, verbatim). "
    "NOT comparable to the flat score above -- different denominator, different meaning. "
    "Read the tree itself for the real payoff: exact localization, and confirmation that "
    "every level matched cleanly (or didn't) down to individual leaf statements."
)


def _range_str(node_range) -> str:
    if node_range is None:
        return "·"
    return f"{node_range.node_type}[{node_range.start_line}:{node_range.end_line}]"


def _dump_hierarchical(alignment, depth: int = 0) -> None:
    indent = "  " * depth
    print(f"{indent}is_leaf={alignment.is_leaf} raw={alignment.raw_score:+.3f} norm={alignment.normalized_score:+.3f}")
    for op in alignment.ops:
        a_text = " / ".join(op.a_lines) if op.a_lines else "·"
        b_text = " / ".join(op.b_lines) if op.b_lines else "·"
        print(
            f"{indent}  [{op.kind:>11}] score={op.score:+.3f}  "
            f"A={_range_str(op.a):32}{a_text!r:50}  B={_range_str(op.b):32}{b_text!r}"
        )
        if op.children is not None:
            _dump_hierarchical(op.children, depth + 2)


def _dump_flat(source_a: str, source_b: str, model_id: str):
    seq_a = normalize_source(source_a)
    seq_b = normalize_source(source_b)
    alignment = flat_align(seq_a, seq_b, model_id=model_id)
    print(f"grid: {len(seq_a)}x{len(seq_b)} = {len(seq_a) * len(seq_b)} cells")
    for op in alignment.ops:
        a_text = " / ".join(op.a_lines) if op.a_lines else "·"
        b_text = " / ".join(op.b_lines) if op.b_lines else "·"
        print(f"  [{op.kind:>11}] score={op.score:+.3f}  A[{op.a_start}:{op.a_end}]={a_text!r:60}  B[{op.b_start}:{op.b_end}]={b_text!r}")
    return alignment


def _run_hierarchical_with_cell_count(source_a: str, source_b: str, model_id: str):
    """Runs align_functions while spying on every align_with_scores call it makes, to
    report the exact sum of m*n DP cells actually computed across the whole recursive
    run -- the real, exact form of the "hierarchical total is smaller than flat" claim,
    not an approximation reconstructed after the fact."""
    grid_sizes = []
    real_align_with_scores = hierarchy.align_with_scores

    def spy(seq_a, seq_b, *call_args, **call_kwargs):
        grid_sizes.append((len(seq_a), len(seq_b)))
        return real_align_with_scores(seq_a, seq_b, *call_args, **call_kwargs)

    hierarchy.align_with_scores = spy
    try:
        cache = EmbeddingCache()
        result = align_functions(source_a, source_b, cache, model_id=model_id)
    finally:
        hierarchy.align_with_scores = real_align_with_scores

    total_cells = sum(m * n for m, n in grid_sizes)
    return result, grid_sizes, total_cells


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("file_a", nargs="?", help="Path to a JS file containing one function")
    parser.add_argument("file_b", nargs="?", help="Path to a JS file containing one function")
    parser.add_argument("--model", default=DEFAULT_MODEL_ID, choices=list(MODEL_REGISTRY), help="Embedding model")
    parser.add_argument("--flat-only", action="store_true", help="Skip the hierarchical run")
    parser.add_argument("--hierarchical-only", action="store_true", help="Skip the flat run")
    args = parser.parse_args()

    if args.file_a and args.file_b:
        source_a = open(args.file_a).read()
        source_b = open(args.file_b).read()
    elif args.file_a or args.file_b:
        parser.error("provide both file_a and file_b, or neither (to run the built-in demo)")
        return
    else:
        print("(no files given -- running the built-in extract-variable-split demo)\n", file=sys.stderr)
        source_a, source_b = DEMO_A, DEMO_B

    print(f"model: {args.model}")

    if not args.hierarchical_only:
        print(f"\n{'=' * 80}\nFLAT (Stage 3a)\n{'=' * 80}")
        flat_alignment = _dump_flat(source_a, source_b, args.model)
        _print_summary("FLAT", flat_alignment.raw_score, flat_alignment.normalized_score, _FLAT_SCOPE)

    if not args.flat_only:
        print(f"\n{'=' * 80}\nHIERARCHICAL (Stage 3b)\n{'=' * 80}")
        result, grid_sizes, total_cells = _run_hierarchical_with_cell_count(source_a, source_b, args.model)
        _dump_hierarchical(result)
        print(f"\ntotal hierarchical DP cells across {len(grid_sizes)} calls: {total_cells}")
        _print_summary("HIERARCHICAL", result.raw_score, result.normalized_score, _HIERARCHICAL_SCOPE)


if __name__ == "__main__":
    main()
