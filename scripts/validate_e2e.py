"""Manual end-to-end validation for Stage 7 against the REAL persisted corpus (not
synthetic fixtures) -- the self-anchor check that originally surfaced the two bugs in
docs/corpus-extraction-bugs.md: a candidate that IS a corpus entry's own
vulnerable_function must resolve "flagged". Anything else on a well-formed entry is
either a real Stage 7 defect or a corpus-quality problem worth investigating
individually, same as those two were.

Restricted to entries where both sides are <= MAX_CHARS characters, purely to keep a
single run tractable -- a handful of real corpus functions (e.g. axios's
dispatchHttpRequest) are 18-24k characters and make hierarchical alignment slow enough
to dominate the whole run. SAMPLE_SIZE/SEED are fixed so re-running this after a corpus
change (e.g. a rebuild) is an apples-to-apples before/after comparison, not a new
random draw.

Run from the repo root:
    PYTHONPATH=. .venv/bin/python scripts/validate_e2e.py
"""
import random
import time

from corpus.controller.store import load_entries
from pipeline.controller.hierarchy import EmbeddingCache
from pipeline.controller.verification import verify_candidate

SAMPLE_SIZE = 15
SEED = 42
MAX_CHARS = 4000


def main() -> None:
    entries = load_entries()
    print(f"Total corpus entries: {len(entries)}")

    small_entries = [
        e for e in entries
        if len(e.vulnerable_function) <= MAX_CHARS and len(e.patched_function) <= MAX_CHARS
    ]
    print(f"Entries with both sides <= {MAX_CHARS} chars: {len(small_entries)}/{len(entries)}")

    random.seed(SEED)
    sample = random.sample(small_entries, min(SAMPLE_SIZE, len(small_entries)))

    no_removed = 0
    no_added = 0
    identical_pairs = 0
    comment_diag_lines = 0
    total_diag_lines = 0
    none_resolutions = 0
    failures: list[tuple[str, str, str]] = []

    cache = EmbeddingCache()

    for i, e in enumerate(sample):
        t0 = time.time()
        if e.vulnerable_function == e.patched_function:
            identical_pairs += 1

        removed = [d for d in e.diagnostic_lines if d.vulnerable_line is not None]
        added = [d for d in e.diagnostic_lines if d.patched_line is not None]
        if not removed:
            no_removed += 1
        if not added:
            no_added += 1
        for d in e.diagnostic_lines:
            total_diag_lines += 1
            stripped = d.text.strip()
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*") or not stripped:
                comment_diag_lines += 1

        try:
            result = verify_candidate(e.vulnerable_function, e, cache)
        except Exception as ex:
            failures.append((e.ghsa_id, e.function_name or "<anonymous>", f"EXCEPTION: {ex}"))
            print(f"  [{i+1}/{len(sample)}] {e.ghsa_id}/{e.function_name}: EXCEPTION {ex} ({time.time()-t0:.1f}s)")
            continue

        for ds in result.diagnostic_scores:
            if ds.vulnerable_line is not None and ds.vulnerable_score is None:
                none_resolutions += 1
            if ds.patched_line is not None and ds.patched_score is None:
                none_resolutions += 1

        flag = "" if result.status == "flagged" else "  <-- NOT FLAGGED"
        print(
            f"  [{i+1}/{len(sample)}] {e.ghsa_id}/{e.function_name}: status={result.status} "
            f"score={result.verification_score:.3f} ({time.time()-t0:.1f}s){flag}"
        )
        if result.status != "flagged":
            failures.append((
                e.ghsa_id, e.function_name or "<anonymous>",
                f"status={result.status} score={result.verification_score:.3f} "
                f"sim_vuln={result.sim_vulnerable:.3f}(fb={result.vulnerable_fallback_used}) "
                f"sim_patched={result.sim_patched:.3f}(fb={result.patched_fallback_used})",
            ))

    print(f"\nSample size: {len(sample)}")
    print(f"Self-anchor pass rate: {len(sample) - len(failures)}/{len(sample)}")
    print(f"Identical vulnerable==patched entries in sample: {identical_pairs} (should be 0 post-fix)")
    print(f"Entries with zero 'removed' diagnostic lines (pure insertion): {no_removed}")
    print(f"Entries with zero 'added' diagnostic lines (pure deletion): {no_added}")
    print(f"Total diagnostic lines across sample: {total_diag_lines}")
    print(f"Diagnostic lines that look like comments/blank: {comment_diag_lines} (should be 0 post-fix)")
    print(f"Diagnostic-line score lookups that resolved to None: {none_resolutions}")
    print(f"\nSelf-anchor failures ({len(failures)}/{len(sample)}):")
    for ghsa, fn, detail in failures:
        print(f"  {ghsa} / {fn}: {detail}")


if __name__ == "__main__":
    main()
