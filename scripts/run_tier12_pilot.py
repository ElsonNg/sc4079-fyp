"""End-to-end 2-example pilot for the Tier-1 (self-check) and Tier-2 (LLM) sets.

Static-only: Tier-1 downloads real npm releases, sha256-verifies them, extracts
with the guarded extractor, and *reads* them with the scanner. No package code is
executed. Tier-2 rewrites vulnerable/patched functions with gemma4:e4b, gates every
output on the corpus diagnostic anchors, and scores survivors through the detector.

Run from the repo root:
    $env:PYTHONPATH="."; .venv\\Scripts\\python.exe scripts\\run_tier12_pilot.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from corpus.controller.sandbox_fetch import (
    SandboxFetchError,
    download_release,
    prune_built_artifacts,
    safe_extract_tarball,
)
from corpus.controller.store import load_entries
from eval.common import DEFAULT_SNAPSHOT_DB, category_for, extension_for, extract_ghsa_ids
from pipeline.controller.candidate_gate import diagnostic_preservation_gate, has_high_signal_anchor
from pipeline.controller.llm_transform import LlmTransformError, OllamaCodeTransformer, TransformConfig
from pipeline.controller.region_detection import RegionDetectorConfig, build_region_detector
from pipeline.controller.scanning import ScanConfig, corpus_fingerprint, scan_directory

SANDBOX_ROOT = Path(__file__).resolve().parent.parent / "eval" / "tier1_sandbox"


def _boundary_complete(entry) -> bool:
    rb = entry.release_boundary or {}
    return all(
        rb.get(key)
        for key in (
            "vulnerable_tarball",
            "vulnerable_artifact_sha256",
            "fixed_tarball",
            "fixed_artifact_sha256",
        )
    )


def _pick_pilot_entries(entries):
    """One JS + one TS entry, different package categories, gateable, resolvable."""
    picked = {}
    used_categories: set[str] = set()
    for entry in entries:
        lang = entry.source_language
        bucket = "javascript" if lang == "javascript" else "typescript"
        if bucket in picked:
            continue
        if not _boundary_complete(entry):
            continue
        if not has_high_signal_anchor(entry.diagnostic_lines, "vulnerable"):
            continue
        category = category_for(entry.package_name)
        if category in used_categories:
            continue
        picked[bucket] = entry
        used_categories.add(category)
        if len(picked) == 2:
            break
    return [picked[k] for k in ("javascript", "typescript") if k in picked]


def _scored_priority(detector, source: str, candidate_id: str, language: str):
    result = detector.detect(source, candidate_id=candidate_id, language=language)
    return result.priority, result


def _flagged_ghsas(summary) -> dict[str, set[str]]:
    by_priority: dict[str, set[str]] = {}
    for finding in summary.findings:
        result = finding["result"]
        priority = result.get("priority", "none")
        by_priority.setdefault(priority, set()).update(extract_ghsa_ids(result))
    return by_priority


def run_tier2(entry, transformer, detector) -> None:
    lang = entry.source_language
    ext = extension_for(lang)
    cid_base = entry.ghsa_id
    print(f"\n  [Tier 2] {entry.ghsa_id} {entry.package_name} ({lang}) fn={entry.function_name}")
    plan = [
        ("type_3", "vulnerable", entry.vulnerable_function, "flagged"),
        ("type_4", "vulnerable", entry.vulnerable_function, "flagged"),
        ("type_3", "patched", entry.patched_function, "cleared"),
    ]
    for clone_type, side, source, expected in plan:
        try:
            code = transformer.transform(source, clone_type=clone_type, side=side, language=lang)
        except LlmTransformError as exc:
            print(f"    {clone_type:7s} {side:10s} GENERATION FAILED: {exc.reason_code}")
            continue
        gate = diagnostic_preservation_gate(
            code,
            entry.diagnostic_lines,
            side=side,
            vulnerable_source=entry.vulnerable_function,
            patched_source=entry.patched_function,
        )
        if not gate.passed:
            print(f"    {clone_type:7s} {side:10s} GATE FAIL: {gate.reason}")
            continue
        priority, _ = _scored_priority(detector, code, f"{cid_base}{ext}", lang)
        if expected == "flagged":
            verdict = "TP" if priority == "automatic_vulnerability" else (
                "abstain" if priority == "manual_review" else "FN")
        else:
            verdict = "FP" if priority == "automatic_vulnerability" else (
                "abstain" if priority == "manual_review" else "TN")
        print(f"    {clone_type:7s} {side:10s} gate=ok priority={priority:22s} -> {verdict}")


def run_tier1(entry, detector, entries) -> None:
    rb = entry.release_boundary
    print(f"\n  [Tier 1] {entry.ghsa_id} {entry.package_name} "
          f"{rb.get('last_affected')} -> {rb.get('first_fixed')}")
    corpus_version = corpus_fingerprint(entries)
    targets = [
        ("vulnerable", rb["vulnerable_tarball"], rb["vulnerable_artifact_sha256"], True),
        ("fixed", rb["fixed_tarball"], rb["fixed_artifact_sha256"], False),
    ]
    for kind, url, sha, is_positive in targets:
        dest = SANDBOX_ROOT / entry.ghsa_id / kind
        try:
            data = download_release(url, sha)
            report = safe_extract_tarball(data, dest)
            pruned = prune_built_artifacts(dest)
        except SandboxFetchError as exc:
            print(f"    {kind:10s} FETCH FAIL: {exc.reason_code} — {exc.detail}")
            continue
        summary = scan_directory(
            dest,
            detector=detector,
            entries=entries,
            config=ScanConfig(
                corpus_version=corpus_version,
                state_path=SANDBOX_ROOT / entry.ghsa_id / f"{kind}-state.json",
            ),
            progress_callback=lambda e: print(f"      {e['phase']}", file=sys.stderr)
            if e["phase"] in {"snapshot_complete", "scan_complete"} else None,
        )
        print(f"    {kind:10s} extracted={report.files_written} "
              f"pruned_dirs={len(pruned.removed_dirs)} pruned_files={len(pruned.removed_files)}")
        by_priority = _flagged_ghsas(summary)
        flagged = by_priority.get("automatic_vulnerability", set())
        review = by_priority.get("manual_review", set())
        present_flagged = entry.ghsa_id in flagged
        present_review = entry.ghsa_id in review
        if is_positive:
            verdict = "TP" if present_flagged else ("abstain" if present_review else "FN")
        else:
            verdict = "FP" if present_flagged else ("abstain" if present_review else "TN")
        print(
            f"    {kind:10s} files={report.files_written:4d} skipped={len(report.skipped_members):3d} "
            f"scanned_fns={summary.total_functions:4d} flagged_ghsa={present_flagged} "
            f"review={present_review} -> {verdict}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT_DB)
    parser.add_argument("--model", default="gemma4:e4b")
    parser.add_argument("--skip-tier1", action="store_true")
    parser.add_argument("--skip-tier2", action="store_true")
    args = parser.parse_args()

    print(f"Loading corpus snapshot: {args.snapshot}")
    entries = load_entries(args.snapshot)
    print(f"  {len(entries)} entries")

    pilot = _pick_pilot_entries(entries)
    if len(pilot) < 2:
        print("Could not pick one JS and one TS gateable entry; aborting.", file=sys.stderr)
        return 2
    print("Pilot picks:")
    for entry in pilot:
        print(f"  - {entry.ghsa_id} {entry.package_name} [{entry.source_language}] "
              f"category={category_for(entry.package_name)}")

    transformer = None
    if not args.skip_tier2:
        transformer = OllamaCodeTransformer(TransformConfig(model=args.model))
        try:
            transformer.ensure_model_available()
            print(f"Ollama model available: {args.model}")
        except LlmTransformError as exc:
            print(f"Ollama model check failed ({exc.reason_code}); skipping Tier 2.", file=sys.stderr)
            transformer = None

    print("Building region detector over the snapshot corpus (loads embedding model)...")
    detector = build_region_detector(
        entries,
        config=RegionDetectorConfig(
            retrieval_top_k=10,
            retrieval_threshold=0.0,
            max_verification_candidates=10,
            same_language_only=True,
        ),
        progress_callback=lambda done, total: print(f"  indexed regions: {done}/{total}", file=sys.stderr)
        if done == total or done % 400 == 0 else None,
    )
    print(f"Detector ready: {len(detector.region_index.pairs)} region pairs")

    if transformer is not None:
        print("\n=== TIER 2 PILOT (LLM-transformed) ===")
        for entry in pilot:
            run_tier2(entry, transformer, detector)

    if not args.skip_tier1:
        print("\n=== TIER 1 PILOT (real-release self-check) ===")
        for entry in pilot:
            run_tier1(entry, detector, entries)

    print("\nPilot complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
