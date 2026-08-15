"""Manual smoke test for pipeline.controller.hierarchy -- real model(s), real snippets.

Prints the full nested alignment tree for process_orders (base vs. extract-variable
split, nested-if variant) and the sanitize-before/after order-sensitivity pair, in the
same indented/annotated style as smoke_test_alignment.py's show(). Useful for eyeballing
before trusting the automated assertions in tests/test_hierarchy.py.

Same calibration caveat as smoke_test_alignment.py: DEFAULT_GAP_PENALTY/
DEFAULT_SPAN_MERGE_PENALTY and get_match_midpoint's probe set are calibrated against
qwen3-embedding-0.6b specifically. Observed directly here: on the sanitize-before/after
pair, qwen3 correctly gaps both swapped statements (recovering at most one
correspondence, as order-preservation requires), but embeddinggemma-300m's weaker
unrelated/related separation lets "sanitize(input);" and "use(input);" cross-match at
swapped positions (both single-argument call expressions, apparently close enough in
its embedding space to clear match_midpoint). tests/test_hierarchy.py's slow tier
deliberately checks DEFAULT_MODEL_ID only, for exactly this reason.

Run from the repo root:
    PYTHONPATH=. .venv/bin/python scripts/smoke_test_hierarchy.py
"""
from pipeline.controller.embedding import MODEL_REGISTRY
from pipeline.controller.hierarchy import EmbeddingCache, align_functions

PROCESS_ORDERS_BASE_NESTED = """
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

PROCESS_ORDERS_SPLIT_RETURN_NESTED = """
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

SANITIZE_BEFORE = """
function handleInput(input) {
    sanitize(input);
    use(input);
}
"""

SANITIZE_AFTER = """
function handleInput(input) {
    use(input);
    sanitize(input);
}
"""


def _range_str(node_range) -> str:
    if node_range is None:
        return "·"
    return f"{node_range.node_type}[{node_range.start_line}:{node_range.end_line}]"


def dump(alignment, depth: int = 0) -> None:
    indent = "  " * depth
    print(f"{indent}is_leaf={alignment.is_leaf} raw={alignment.raw_score:+.3f} norm={alignment.normalized_score:+.3f}")
    for op in alignment.ops:
        a_text = " / ".join(op.a_lines) if op.a_lines else "·"
        b_text = " / ".join(op.b_lines) if op.b_lines else "·"
        print(
            f"{indent}  [{op.kind:>11}] score={op.score:+.3f}  "
            f"A={_range_str(op.a):35}{a_text!r:45}  B={_range_str(op.b):35}{b_text!r}"
        )
        if op.children is not None:
            dump(op.children, depth + 2)


def show(title: str, source_a: str, source_b: str, model_id: str) -> None:
    cache = EmbeddingCache()
    result = align_functions(source_a, source_b, cache, model_id=model_id)
    print(f"\n=== [{model_id}] {title} ===")
    dump(result)


if __name__ == "__main__":
    for model_id in MODEL_REGISTRY:
        print(f"\n{'#' * 80}\n# model: {model_id}\n{'#' * 80}")
        show(
            "process_orders (nested if/else): base vs. extract-variable split",
            PROCESS_ORDERS_BASE_NESTED, PROCESS_ORDERS_SPLIT_RETURN_NESTED, model_id,
        )
        show("sanitize-before vs. sanitize-after (order swap)", SANITIZE_BEFORE, SANITIZE_AFTER, model_id)
