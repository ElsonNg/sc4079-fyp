"""Generate the Tier-2 LLM-transformed candidate set with gemma4:e4b.

Positives are Type-3 and Type-4 rewrites of each entry's vulnerable function;
negatives are paraphrased patched functions. Every rewrite is passed through the
diagnostic-anchor preservation gate before it is written, so the LLM cannot
silently flip a label. Records reuse the existing candidate/negative schema so the
scorer and any downstream tooling stay compatible.

Run from the repo root:
    $env:PYTHONPATH="."; .venv\\Scripts\\python.exe scripts\\generate_llm_transformed_subset.py
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

from corpus.controller.store import load_entries
from eval.common import DEFAULT_SNAPSHOT_DB, category_for
from pipeline.controller.candidate_gate import diagnostic_preservation_gate, has_high_signal_anchor
from pipeline.controller.llm_transform import LlmTransformError, OllamaCodeTransformer, TransformConfig
from scripts.generate_candidate_subset import digest, entry_key

POSITIVE_OUTPUT = Path(__file__).resolve().parent.parent / "eval" / "llm_transformed_positive.jsonl"
NEGATIVE_OUTPUT = Path(__file__).resolve().parent.parent / "eval" / "llm_transformed_negative.jsonl"
MAX_ATTEMPTS = 3


def _select_entries(entries, *, total: int, per_category: int):
    by_category: dict[str, list] = defaultdict(list)
    for entry in entries:
        if not has_high_signal_anchor(entry.diagnostic_lines, "vulnerable"):
            continue
        by_category[category_for(entry.package_name)].append(entry)
    selected: list = []
    for category, bucket in sorted(by_category.items()):
        js = [e for e in bucket if e.source_language == "javascript"]
        ts = [e for e in bucket if e.source_language != "javascript"]
        interleaved: list = []
        for a, b in zip(js, ts):
            interleaved.extend([a, b])
        interleaved.extend(js[len(ts):] if len(js) > len(ts) else ts[len(js):])
        selected.extend(interleaved[:per_category])
    return selected[:total]


def _base_record(entry, candidate_source: str, clone_type: str) -> dict:
    return {
        "generation_method": "llm_transform_gemma4:e4b",
        "clone_type": clone_type,
        "transformation_family": f"llm_{clone_type}",
        "corpus_entry": entry_key(entry),
        "package_name": entry.package_name,
        "category": category_for(entry.package_name),
        "ecosystem": entry.ecosystem,
        "osv_id": entry.osv_id,
        "severity": entry.severity,
        "cwes": [c.model_dump() for c in entry.cwes],
        "osv_confirmed": entry.osv_confirmed,
        "source_language": entry.source_language,
        "affected_versions": entry.affected_versions,
        "fixed_versions": entry.fixed_versions,
        "vulnerable_source_sha256": digest(entry.vulnerable_function),
        "patched_source_sha256": digest(entry.patched_function),
        "candidate_source_sha256": digest(candidate_source),
        "vulnerable_function": entry.vulnerable_function,
        "patched_function": entry.patched_function,
        "diagnostic_lines": [line.model_dump() for line in entry.diagnostic_lines],
        "candidate_source": candidate_source,
    }


def _generate_one(transformer, entry, *, clone_type, side):
    source = entry.vulnerable_function if side == "vulnerable" else entry.patched_function
    # Type-4 (semantic reimplementation) needs a hotter sample to diverge from the
    # original; each retry raises the temperature further to escape an echo.
    base = 0.85 if clone_type == "type_4" else 0.5
    last_reason = "unknown"
    for attempt in range(MAX_ATTEMPTS):
        try:
            code = transformer.transform(
                source,
                clone_type=clone_type,
                side=side,
                language=entry.source_language,
                temperature=min(base + 0.15 * attempt, 1.1),
            )
        except LlmTransformError as exc:
            return None, f"generation_{exc.reason_code}"
        gate = diagnostic_preservation_gate(
            code,
            entry.diagnostic_lines,
            side=side,
            vulnerable_source=entry.vulnerable_function,
            patched_source=entry.patched_function,
        )
        if gate.passed:
            return code, "ok"
        last_reason = gate.reason
    return None, last_reason


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT_DB)
    parser.add_argument("--model", default="gemma4:e4b")
    parser.add_argument("--entries", type=int, default=60, help="total corpus entries to sample")
    parser.add_argument("--per-category", type=int, default=10)
    parser.add_argument("--pilot", action="store_true", help="tiny 2-entry run")
    args = parser.parse_args()

    if args.pilot:
        args.entries, args.per_category = 2, 1

    entries = load_entries(args.snapshot)
    transformer = OllamaCodeTransformer(TransformConfig(model=args.model))
    transformer.ensure_model_available()

    sampled = _select_entries(entries, total=args.entries, per_category=args.per_category)
    print(f"Sampled {len(sampled)} entries across "
          f"{len({category_for(e.package_name) for e in sampled})} categories")

    positives: list[dict] = []
    negatives: list[dict] = []
    attrition: Counter = Counter()

    for index, entry in enumerate(sampled, start=1):
        print(f"[{index}/{len(sampled)}] {entry.ghsa_id} {entry.package_name} ({entry.source_language})")
        for clone_type in ("type_3", "type_4"):
            code, reason = _generate_one(transformer, entry, clone_type=clone_type, side="vulnerable")
            attrition[f"positive_{clone_type}_{reason}"] += 1
            if code is not None:
                record = _base_record(entry, code, clone_type)
                record.update({"candidate_id": f"L{len(positives) + 1:03d}", "expected_status": "flagged"})
                positives.append(record)
        code, reason = _generate_one(transformer, entry, clone_type="type_3", side="patched")
        attrition[f"negative_patched_{reason}"] += 1
        if code is not None:
            record = _base_record(entry, code, "type_3")
            record.update({
                "candidate_id": f"LN{len(negatives) + 1:03d}",
                "expected_status": "cleared",
                "negative_category": "patched",
            })
            negatives.append(record)

    POSITIVE_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with POSITIVE_OUTPUT.open("w", encoding="utf-8") as handle:
        for record in positives:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    with NEGATIVE_OUTPUT.open("w", encoding="utf-8") as handle:
        for record in negatives:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(f"\nWrote {len(positives)} positives -> {POSITIVE_OUTPUT}")
    print(f"Wrote {len(negatives)} negatives -> {NEGATIVE_OUTPUT}")
    print("Gate/generation attrition:")
    for key, count in sorted(attrition.items()):
        print(f"  {key}: {count}")
    kept_by_type = Counter(r["clone_type"] for r in positives)
    print(f"Positives by clone type: {dict(kept_by_type)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
