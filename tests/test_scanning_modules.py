"""Compatibility of saved scan state with the extracted scanning modules."""

import json
from dataclasses import asdict
from pathlib import Path

from provtrail.pipeline.detection.config import RegionDetectorConfig
from provtrail.pipeline.scanning import cache


def test_saved_cache_rebinds_nested_region_ids_after_function_moves(tmp_path):
    fixture = json.loads(
        (Path(__file__).parent / "fixtures" / "region_model_contracts.json").read_text(encoding="utf-8")
    )["payloads"]["vulnerable"]["payload"]
    old_id = "src/old.js::0:40"
    new_id = "src/new.js::0:40"
    old_region = f"candidate:{old_id}:function"
    new_region = f"candidate:{new_id}:function"
    fixture["candidate_id"] = old_id
    fixture["aggregates"][0]["top_matches"][0]["candidate_region_id"] = old_region
    fixture["evidence"][0]["candidate_region_id"] = old_region

    (tmp_path / "source.js").write_text("function example() {}", encoding="utf-8")
    snapshot = cache.build_merkle_snapshot(tmp_path)
    config = RegionDetectorConfig()
    fingerprint = cache.fingerprint_config({
        "detector": asdict(config),
        "result_cache_schema": cache.RESULT_CACHE_SCHEMA_VERSION,
    })
    state_path = tmp_path / ".provtrail" / "scan-state.json"
    cache.save_scan_state(cache.ScanState(
        target_root=str(tmp_path), corpus_version="corpus-v1",
        detector_config_fingerprint=fingerprint, snapshot=snapshot,
        result_cache={"same-content": {"function_hash": "same-content", "result": fixture}},
    ), state_path)

    prepared = cache.prepare_scan_cache(tmp_path, state_path, "corpus-v1", config, snapshot)
    rebound = prepared.result_for({"function_hash": "same-content", "function_id": new_id})

    assert prepared.context_matches
    assert rebound is not None
    assert rebound.candidate_id == new_id
    assert rebound.aggregates[0].top_matches[0].candidate_region_id == new_region
    assert rebound.evidence[0].candidate.region_id == new_region
