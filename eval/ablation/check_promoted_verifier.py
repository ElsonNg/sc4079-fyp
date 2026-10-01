"""Check production integration against frozen retrieval; does not run embeddings."""
import argparse
from dataclasses import fields
import json
import inspect
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from eval.ablation.common import digest, file_hash, read_jsonl, unseal
from eval.ablation.exact_similarity import exact_backend
from eval.ablation import run_region_types as runner
from eval.ablation.run_expanded_correspondence import quality, write
from eval.ablation.expanded_correspondence import recheck as experimental_recheck
from eval.ablation.priority_relationships import RevisionRelationships as ExperimentalRelationships
from eval.metrics import expected_retrieval_fields
from provtrail.corpus.integrations.sqlite_store import load_entries
from provtrail.pipeline.controller import region_detection as controller
from provtrail.pipeline.controller.hashing import build_hash_index
from provtrail.pipeline.controller.region_extraction import extract_corpus_region_pairs
from provtrail.pipeline.detection.config import RegionDetectorConfig, RegionVerifierConfig
from provtrail.pipeline.models.result import RegionDetectionResult
from provtrail.pipeline.scanning.project_context import ProjectEvidenceIndex


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=runner.ROOT / "eval/frozen/active-block-function-gpu-v1")
    parser.add_argument("--experiment", type=Path, default=runner.ROOT / "eval/frozen/active-expanded-correspondence-v1")
    parser.add_argument("--output", type=Path, default=runner.ROOT / "eval/frozen/active-promoted-verifier-v1")
    args = parser.parse_args(argv)
    source, experiment, output = (p.resolve() for p in (args.source, args.experiment, args.output))
    assert not output.exists() or not any(output.iterdir()), "Use a fresh output directory"
    assert not any(output.is_relative_to(p) or p.is_relative_to(output) for p in (source, experiment))
    lock = unseal(json.loads((source / "study-lock.json").read_text(encoding="utf-8")))
    expected_report = json.loads((experiment / "summary.json").read_text(encoding="utf-8"))
    assert digest(lock) == expected_report["source_study"]
    assert all(file_hash(v["path"]) == v["sha256"] for v in lock["inputs"].values())
    assert all(file_hash(runner.ROOT / p) == sha for p, sha in expected_report["code_sha256"].items())
    # Original production code has intentionally changed; retain that provenance.
    changed_original_code = [p for p, sha in lock["code"].items() if file_hash(runner.ROOT / p) != sha]
    assignments = json.loads(Path(lock["inputs"]["split"]["path"]).read_text(encoding="utf-8"))["assignments"]
    records = [dict(r, split=assignments[r["candidate_id"]]["split"])
               for tier in ("tier1", "tier2") for r in read_jsonl(lock["inputs"][tier]["path"])]
    assert [r["candidate_id"] for r in records] == lock["candidate_ids"]
    saved_changes = json.loads((experiment / "case-changes.json").read_text(encoding="utf-8"))["changes"]
    saved_changes = {r["candidate_id"]: r for r in saved_changes if r["arm"] == "expanded_ast"}
    entries = load_entries(lock["inputs"]["reference"]["path"])
    pairs = extract_corpus_region_pairs(entries)
    pair_map = {p.pair_id: p for p in pairs}
    experimental_relationships = ExperimentalRelationships.from_entries(entries)
    verifier = RegionVerifierConfig(**{f.name: lock["detector"]["verifier"][f.name] for f in fields(RegionVerifierConfig)})
    config_fields = {f.name for f in fields(RegionDetectorConfig)} - {"verifier", "include_expanded_correspondence_fallback"}
    config = RegionDetectorConfig(**{k: v for k, v in lock["detector"].items() if k in config_fields}, verifier=verifier)
    detector = controller.RegionDetector(entries, SimpleNamespace(pairs=pairs), build_hash_index(entries), config)
    project = ProjectEvidenceIndex(root=runner.ROOT)
    rows, checkpoints = [], {}
    with exact_backend():
        for i, record in enumerate(records, 1):
            path = runner.checkpoint_path(source, "block_function", 1, record["candidate_id"])
            raw = json.loads(path.read_text(encoding="utf-8"))
            body = unseal(raw)
            assert body["identity"] == digest([digest(lock), "block_function", 1, record])
            old = body["row"]
            baseline = RegionDetectionResult.model_validate(old["result"])
            expected, _ = experimental_recheck(baseline, record["candidate_source"], record["source_language"],
                                              pair_map, experimental_relationships, verifier, mode="expanded_ast")
            if record["candidate_id"] in saved_changes:
                saved_expected = RegionDetectionResult.model_validate(saved_changes[record["candidate_id"]]["result"])
                assert expected.model_dump(mode="json") == saved_expected.model_dump(mode="json")
            # Only retrieval and its initial pair comparisons are supplied from the
            # checkpoint. Main classification, attribution, priority, hash lookup,
            # whole-function checks and final project assessment run in production.
            with patch.object(controller, "aggregate_retrieval_matches", return_value=baseline.aggregates), \
                 patch.object(detector, "_verify_regions", return_value=baseline.evidence):
                actual = detector.detect(record["candidate_source"], candidate_id=record["candidate_id"],
                                         language=record["source_language"], _matches=[])
            fields_expected = expected_retrieval_fields(record)
            targets = {p.fix_boundary_id for p in pairs
                       if (p.origin.fix_commit_sha, p.origin.file_path.replace("\\", "/"), p.origin.function_name) == fields_expected[1:]
                       and fields_expected[0] in {a.ghsa_id for a in [p.advisory, *p.advisories]}
                       and p.origin.source_language == record["source_language"]}
            assert targets
            actual_quality = quality(old, actual, targets)
            expected_quality = quality(old, expected, targets)
            for k in ("priority", "correct_origin_automatic", "wrong_origin_automatic", "patched_false_positive", "abstained", "boundaries"):
                assert actual_quality[k] == expected_quality[k], (record["candidate_id"], k)
            # Compare the serialized evidence contract used by the checkpoints.
            actual_states = [s.to_record() for s in actual.vulnerability_states]
            expected_states = [s.to_record() for s in expected.vulnerability_states]
            assert actual_states == expected_states, (record["candidate_id"], [
                {k: [a.get(k), b.get(k)] for k in a.keys() | b.keys() if a.get(k) != b.get(k)}
                for a, b in zip(actual_states, expected_states)
            ])
            assert [s.model_dump(mode="json") for s in actual.lineages] == [s.model_dump(mode="json") for s in expected.lineages], record["candidate_id"]
            cached = RegionDetectionResult.model_validate_json(actual.model_dump_json())
            assert project.assess(cached, "candidate.js").priority == actual.priority
            rows.append(actual_quality)
            checkpoints[record["candidate_id"]] = raw["content_sha256"]
            if i % 100 == 0:
                print(f"Checked production integration {i}/{len(records)}", flush=True)
    assert digest(checkpoints) == expected_report["checkpoint_set_sha256"]
    scopes = []
    for saved in expected_report["scopes"]:
        if saved["arm"] != "expanded_ast":
            continue
        selected = [r for r in rows if (saved["tier"] == "combined" or r["tier"] == saved["tier"])
                    and (saved["split"] == "all" or r["split"] == saved["split"])
                    and (saved["route"] == "all" or r["hash_path"] == (saved["route"] == "hash"))]
        metrics = runner.metrics(selected)
        assert metrics == saved["recheck"]
        scopes.append(dict(tier=saved["tier"], split=saved["split"], route=saved["route"], metrics=metrics))
    paths = ["eval/ablation/check_promoted_verifier.py",
             "src/provtrail/pipeline/controller/correspondence_verification.py", "src/provtrail/pipeline/controller/ast_correspondence.py",
             "src/provtrail/pipeline/detection/revision_relationships.py", "src/provtrail/pipeline/detection/config.py",
             "src/provtrail/pipeline/models/result.py", "src/provtrail/pipeline/scanning/project_context.py", "src/provtrail/pipeline/scanning/cache.py"]
    write(output / "summary.json", dict(policy="expanded_ast_v1", case_count=len(rows), scopes=scopes,
        source_study=digest(lock), checkpoint_set_sha256=digest(checkpoints),
        experiment_summary_sha256=file_hash(experiment / "summary.json"),
        production_code_sha256={p: file_hash(runner.ROOT / p) for p in paths},
        # Scope the controller hash to detection, excluding unrelated index-builder edits.
        production_detector_class_sha256=digest(inspect.getsource(controller.RegionDetector)),
        changed_original_code=changed_original_code,
        note="CPU integration replay: frozen retrieval and initial region comparisons; fresh production hash lookup, classification, lineage, revision priority, expanded verification, JSON cache roundtrip and project assessment. Every final boundary state, lineage and quality metric matches the selected expanded_ast experiment. No GPU, fresh retrieval or end-to-end timing."))
    print(f"Verified {len(rows)} cases and {len(scopes)} metric scopes", flush=True)


if __name__ == "__main__":
    main()
