"""Manual smoke test for pipeline.controller.alignment -- real model(s), real snippets.

Runs every case against both models in MODEL_REGISTRY (qwen3-embedding-0.6b,
embeddinggemma-300m) for comparison. Note: DEFAULT_GAP_PENALTY/DEFAULT_MATCH_MIDPOINT/
DEFAULT_SPAN_MERGE_PENALTY in alignment.py were calibrated against qwen3-embedding-0.6b's
cosine similarity behavior specifically -- embeddinggemma-300m may have a different
similarity distribution for the same lines, so its results below use the same constants
uncalibrated for it. Worth noting, not necessarily worth fixing unless embeddinggemma is
adopted as more than a comparison model.

Run from the repo root:
    PYTHONPATH=. .venv/bin/python scripts/smoke_test_alignment.py
"""
from pipeline.controller.alignment import align
from pipeline.controller.embedding import MODEL_REGISTRY
from pipeline.controller.parsing import normalize_source

BASE = """
function processOrders(orders) {
    let total = 0;
    for (let i = 0; i < orders.length; i++)
        total += orders[i].price * orders[i].quantity;
    return total;
}
"""

# Identical to BASE except the return statement is split into a variable declaration plus
# return, via extract-variable.
SPLIT_RETURN = """
function processOrders(orders) {
    let total = 0;
    for (let i = 0; i < orders.length; i++)
        total += orders[i].price * orders[i].quantity;
    const result = total;
    return result;
}
"""

TRANSFER_A = """
function transfer(sender, receiver, amount) {
    let balance = sender.balance;
    if (balance < amount) { throw new Error('insufficient'); }
    sender.balance = balance - amount;
    receiver.balance = receiver.balance + amount;
    return receiver.balance;
}
"""

UNRELATED = """
function formatDate(date) {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    return `${year}-${month}`;
}
"""


def show(title: str, source_a: str, source_b: str, model_id: str) -> None:
    seq_a = normalize_source(source_a)
    seq_b = normalize_source(source_b)
    alignment = align(seq_a, seq_b, model_id=model_id)

    print(f"\n=== [{model_id}] {title} ===")
    print(f"a: {len(seq_a)} lines, b: {len(seq_b)} lines")
    print(f"raw_score={alignment.raw_score:.4f}  normalized_score={alignment.normalized_score:.4f}")
    for op in alignment.ops:
        a_text = " / ".join(op.a_lines) if op.a_lines else "·"
        b_text = " / ".join(op.b_lines) if op.b_lines else "·"
        print(
            f"  [{op.kind:>11}] score={op.score:+.3f}  "
            f"A[{op.a_start}:{op.a_end}]={a_text!r:60}  B[{op.b_start}:{op.b_end}]={b_text!r}"
        )


def show_minimal_unrelated_merge_repro(model_id: str) -> None:
    """Regression check for the span-merge-as-cheap-gap-substitute fix: 3 genuinely
    unrelated lines vs 1 genuinely unrelated line. Before the fix this produced a phantom
    span_merge (score -0.25, beating 4 honest gaps at -0.28 purely on gap-avoidance
    arithmetic, on qwen3-embedding-0.6b). After the fix, span_merge candidates are gated on
    a positive raw score, so this should now produce 4 plain gaps and no span_merge at all
    -- on either model, since the gate itself is model-agnostic even though the exact
    scores it's gating on are not."""
    seq_a = [
        "let balance = sender.balance;",
        "if (balance < amount) { throw new Error('insufficient'); }",
        "sender.balance = balance - amount;",
    ]
    seq_b = ["const month = String(date.getMonth() + 1).padStart(2, '0');"]

    alignment = align(seq_a, seq_b, model_id=model_id)

    print(f"\n=== [{model_id}] minimal unrelated-merge repro (span-merge gating regression check) ===")
    print(f"raw_score={alignment.raw_score:.4f}")
    for op in alignment.ops:
        a_text = " / ".join(op.a_lines) if op.a_lines else "·"
        b_text = " / ".join(op.b_lines) if op.b_lines else "·"
        print(f"  [{op.kind:>11}] score={op.score:+.3f}  A[{op.a_start}:{op.a_end}]={a_text!r:60}  B[{op.b_start}:{op.b_end}]={b_text!r}")
    if any(op.kind == "span_merge" for op in alignment.ops):
        print("  UNEXPECTED: a span_merge op appeared -- the gating fix may have regressed.")
    else:
        print("  OK: no span_merge op -- all gaps, as expected post-fix.")


if __name__ == "__main__":
    for model_id in MODEL_REGISTRY:
        print(f"\n{'#' * 80}\n# model: {model_id}\n{'#' * 80}")
        show("process_orders: base vs. extract-variable split", BASE, SPLIT_RETURN, model_id)
        show("transfer: identical vs. identical (sanity)", TRANSFER_A, TRANSFER_A, model_id)
        show("transfer vs. unrelated (formatDate)", TRANSFER_A, UNRELATED, model_id)
        show_minimal_unrelated_merge_repro(model_id)
