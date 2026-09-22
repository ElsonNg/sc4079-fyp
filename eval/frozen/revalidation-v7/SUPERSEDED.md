# Superseded by revalidation-v7-utf8

Snippet execution completed, but the resume verification failed: the older JSONL reader used `str.splitlines()`, which incorrectly split valid Unicode characters U+0085/U+2028/U+2029 inside JSON strings. The cookie tests exposed this with byte-valued controls.

This run is retained as evidence of that tooling failure. Use `../revalidation-v7-utf8/` and `eval.tier2.extend_validation_v2` for the verified batch. The new version changes the JSONL record reader to split only at LF and preserves the raw observations. No corpus snippet was repaired or relabelled to address this issue.
