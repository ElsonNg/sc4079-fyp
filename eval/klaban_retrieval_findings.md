# Klaban retrieval evaluation findings

## Recall@10 — 2026-08-17

The imported Klaban corpus was evaluated against the Qwen3-Embedding-0.6B
whole-function window index with `k=10`. A hit requires the expected identity tuple
(`ghsa_id`, fix commit, file path, and function name) to appear in the aggregated top
10 results.

| Query side | Queries | Hits | Misses | Recall@10 |
|---|---:|---:|---:|---:|
| Vulnerable | 1,529 | 1,528 | 1 | 99.9346% |
| Patched | 1,335 | 1,318 | 17 | 98.7266% |
| Combined | 2,864 | 2,846 | 18 | 99.3715% |

Raw result:

```json
{
  "k": 10,
  "vulnerable_queries": 1529,
  "vulnerable_hits": 1528,
  "vulnerable_recall_at_k": 0.999345977763244,
  "patched_queries": 1335,
  "patched_hits": 1318,
  "patched_recall_at_k": 0.9872659176029962
}
```

### Interpretation

- Vulnerable Recall@10 is effectively complete, with one missed corpus identity.
- Patched Recall@10 is also strong: 17 patched functions did not retrieve their
  corresponding vulnerable entry in the top 10.
- The combined result is 2,846 successful queries out of 2,864.
- This measures retrieval coverage, not classification accuracy or precision.
  Vulnerable queries originate from the indexed corpus, so that side is primarily a
  self-retrieval sanity check.
- A patched-side hit means the relevant advisory was retrieved; it does not mean the
  patched function was classified as vulnerable. Vulnerable-versus-patched
  verification remains a downstream responsibility.

### Evaluation context and limitations

- Model: `qwen3-embedding-0.6b` (`Qwen/Qwen3-Embedding-0.6B`).
- Retrieval depth: `k=10`.
- Query workload: 2,864 functions represented by 34,554 bounded query windows.
- Corpus representation: 6,653 diagnostic-aware windows across 1,678 total corpus
  entries, including 1,529 Klaban entries.
- The local CPU-compatible Qwen configuration uses a 64-token sequence cap. Results
  therefore characterize this bounded-window configuration, not an uncapped model.
- The evaluator does not currently list failed identities or reuse query embeddings
  across different values of `k`.

## Planned comparison

Run Recall@5 next and append its raw result and interpretation here. Comparing
Recall@5 with Recall@10 will quantify how many of the 18 successful-at-10 cases fall
outside the first five positions.
