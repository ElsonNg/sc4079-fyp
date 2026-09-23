"""Current validated corpus inputs; frozen historical runs remain separate."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent
TIER1_LABELS = ROOT / "tier1_release_labels.jsonl"
TIER1_CORPUS = ROOT / "corpus.db"
TIER2_CASES = ROOT / "tier2_cases.jsonl"
TIER2_ELIGIBLE_PAIRS = ROOT / "tier2_eligible_pairs.jsonl"
TIER2_PRUNED = ROOT / "tier2_pruned.jsonl"
SUMMARY = ROOT / "summary.json"
