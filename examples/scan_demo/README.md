# Scan demo

This is a small target project for exercising the `provtrail` scanner. It contains:

- `vulnerable_clone.js`: the existing C01 transformed vulnerable Axios proxy clone;
- `patched_clone.js`: the corresponding patched Axios function;
- `benign.js`: the existing hierarchy-demo authorization example.
- `candidates/`: C02–C30 materialized from the existing 30-candidate evaluation set;
- `candidates/manifest.json`: candidate IDs, transformations, CVEs, and expected statuses.

C10 and C30 were standalone class-method snippets in the evaluation fixture, so the
demo files place those method bodies inside a minimal JavaScript class.

From the repository root, run:

```bash
python3 -m cli scan examples/scan_demo --output /tmp/scan-demo.json
```

The first scan may build or load the local embedding index. Repeat the command to
observe Merkle-state reuse. The vulnerable clone should be retained as `flagged` or
`manual_review`; the patched and benign examples are controls and may be `cleared` or
sent to `manual_review` depending on the configured evidence thresholds.
