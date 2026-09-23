import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1] / "eval/frozen/tier1-expansion-v1"


def _rows(name: str) -> list[dict]:
    return [json.loads(line) for line in (ROOT / name).read_text(encoding="utf-8").splitlines()]


def test_tier1_replacements_are_distinct_and_paired():
    pairs = _rows("pairs.jsonl")
    cases = _rows("cases.jsonl")
    combined = _rows("combined-valid-cases.jsonl")
    assert (len(pairs), len(cases), len(combined)) == (26, 52, 600)
    assert len({tuple(pair["origin"]) for pair in pairs}) == 26
    assert len({(pair["vulnerable_function_sha256"], pair["patched_function_sha256"]) for pair in pairs}) == 26
    assert len({case["candidate_id"] for case in combined}) == 600
    by_pair = {}
    for case in cases:
        by_pair.setdefault(case["pair_id"], []).append(case)
        assert case["checks"]["source_exact_in_release_tarball"]
        assert case["verdict"] == "valid_advisory_reference"
    assert all({case["reference_side"] for case in pair_cases} == {"vulnerable", "patched"} for pair_cases in by_pair.values())


def test_tier1_replacement_sources_and_file_lock():
    for pair in _rows("pairs.jsonl"):
        for side, key in (("vulnerable", "vulnerable_function"), ("patched", "patched_function")):
            assert hashlib.sha256(pair[key].encode("utf-8")).hexdigest() == pair[f"{side}_function_sha256"]
        assert pair["vulnerable_function_sha256"] != pair["patched_function_sha256"]
        assert pair["changed_lines"]
    lock = json.loads((ROOT / "lock.json").read_text(encoding="utf-8"))
    for name, digest in lock.items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest
