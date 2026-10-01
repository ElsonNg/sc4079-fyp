"""Replay the relationship policy using the unchanged v1 checkpoint reader."""
from collections import Counter
from contextlib import ExitStack
import json
from pathlib import Path
from unittest.mock import patch

from eval.ablation import run_priority_replay as runner
from eval.ablation.common import file_hash, unseal
from eval.ablation.priority_relationships import (
    POLICY, RevisionRelationships, experimental_priority, review_alternatives,
)
from provtrail.corpus.integrations.sqlite_store import load_entries
from provtrail.pipeline.models.result import RegionDetectionResult


DEFAULT_OUTPUT = runner.runner.ROOT / "eval/frozen/active-priority-relationships-v2"
DESCRIPTION = (
    "With a verified patched boundary: connected revisions retain review, even below the edit-side threshold. "
    "Other review-causing alternatives retain review unless their identity is explicitly incompatible "
    "(different known code families, conflicting function identity, no broader correspondence, "
    "and both edit anchors explicitly generic). Missing edges, different paths, unknown identity "
    "and low scores alone do not establish incompatibility. Existing S/T-failed noise handling remains, "
    "except when an exact revision connection makes it relevant. Hash decisions, verified vulnerable "
    "findings and conflict handling are preserved. Cases without a verified patch retain the original policy."
)


def write_lf(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))


def main(argv=None):
    traces, catalogs = [], {}
    original_replay = runner.replay_row

    def catalog(result):
        assert len(catalogs) == 1, "Replay requires one shared frozen reference corpus"
        return next(iter(catalogs.values()))

    def priority(result, threshold):
        return experimental_priority(result, catalog(result))

    def replay(row, threshold):
        value = RegionDetectionResult.model_validate(row["result"])
        eligible = not value.hash_matches and not any(s.status == "vulnerable" for s in value.vulnerability_states)
        decisions = review_alternatives(value, catalog(value)) if eligible and any(
            s.status == "patched" for s in value.vulnerability_states) else []
        new, protected = original_replay(row, threshold)
        traces.append(dict(arm=row["arm"], candidate_id=row["candidate_id"], tier=row["tier"],
                           split=row["split"], expected_status=row["expected_status"],
                           before=row["priority"], after=new["priority"], alternatives=decisions))
        return new, protected

    # Read source locks without changing them; the underlying runner independently
    # verifies the complete first-repeat checkpoints, source bytes and summaries.
    import argparse
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--source", type=Path, action="append")
    options, _ = parser.parse_known_args(argv)
    for source in options.source or runner.DEFAULT_SOURCES:
        study = unseal(json.loads((source / "study-lock.json").read_text(encoding="utf-8")))
        spec = study["inputs"]["reference"]
        assert file_hash(spec["path"]) == spec["sha256"]
        if spec["sha256"] not in catalogs:
            catalogs[spec["sha256"]] = RevisionRelationships.from_entries(load_entries(spec["path"]))
    assert len(catalogs) == 1, "Source studies must share one reference corpus"
    with ExitStack() as stack:
        for name, replacement in (("POLICY", POLICY), ("DEFAULT_OUTPUT", DEFAULT_OUTPUT),
                                  ("experimental_priority", priority), ("replay_row", replay), ("write_json", write_lf)):
            stack.enter_context(patch.object(runner, name, replacement))
        runner.main(argv)
    # Locate the chosen output without changing original study artifacts.
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args, _ = parser.parse_known_args(argv)
    output = args.output.resolve()
    report = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    relationships = next(iter(catalogs.values()))
    report.update(policy_sha256=file_hash(Path(__file__).with_name("priority_relationships.py")),
                  adapter_sha256=file_hash(Path(__file__)), relationship_policy=DESCRIPTION,
                  reference_sha256=next(iter(catalogs)), revision_links=relationships.links)
    write_lf(output / "summary.json", report)
    write_lf(output / "relationship-traces.json", {"policy": POLICY, "cases": traces})
    changed = json.loads((output / "case-changes.json").read_text(encoding="utf-8"))
    write_lf(output / "case-changes.json", changed)
    lines = (output / "tables.md").read_text(encoding="utf-8").splitlines()
    lines = [DESCRIPTION if line.startswith("Only when a verified patched boundary exists:") else line for line in lines]
    lines += ["", "## Revision relationships", "",
              f"{len(relationships.links)} exact patched-to-vulnerable links in the shared corpus. Connections establish equal source revisions, not a complete chronology or Git ancestry.", "",
              "Relationship diagnostics for each case are in `relationship-traces.json`. Connected revisions and unknown alternatives may overlap within a case.", ""]
    for split in ("tuning", "evaluation", "all"):
        selected = [t for t in traces if t["arm"] == "block_function" and t["tier"] == "tier2"
                    and (split == "all" or t["split"] == split)]
        counts = Counter(d["relationship"] for t in selected for d in t["alternatives"])
        lines.append(f"Block/function {split}: review-relevant boundary counts {dict(counts)}.")
    (output / "tables.md").write_bytes(("\n".join(lines) + "\n").encode("utf-8"))


if __name__ == "__main__":
    main()
