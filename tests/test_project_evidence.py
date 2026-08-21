import json

from pipeline.controller.project_evidence import build_project_evidence
from pipeline.models.provenance import AdvisoryAlias
from pipeline.models.regions import (
    LineageAttribution, PackageApplicability, RegionDetectionResult, VulnerabilityState,
)


def _result(package="axios"):
    alias = AdvisoryAlias(ghsa_id="GHSA-test", package_name=package, ecosystem="npm")
    return RegionDetectionResult(
        priority="manual_review", candidate_region_count=0, retrieval_match_count=0,
        lineages=[LineageAttribution(
            lineage_id="lineage", confidence="high", score=1.0, repo="owner/repo",
            file_path="lib/code.js", reference_function="run", associated_advisories=[alias],
        )],
        vulnerability_states=[VulnerabilityState(
            lineage_id="lineage", fix_boundary_id="boundary", fix_commit_sha="fix",
            status="vulnerable", fix_evidence=["added fix signature absent"], advisories=[alias],
        )],
        package_applicabilities=[PackageApplicability(
            lineage_id="lineage", package=package, ecosystem="npm",
        )],
    )


def test_installed_package_ownership_confirms_and_enables_automatic_priority(tmp_path):
    package = tmp_path / "node_modules" / "axios"
    package.mkdir(parents=True)
    (package / "package.json").write_text(json.dumps({"name": "axios", "version": "1.0.0"}))
    (package / "index.js").write_text("function run() { return 1; }")
    evidence = build_project_evidence(tmp_path, ["node_modules/axios/index.js"])

    result = evidence.assess(_result(), "node_modules/axios/index.js")

    assert result.package_applicabilities[0].status == "confirmed"
    assert result.priority == "automatic_vulnerability"


def test_first_party_copy_without_upstream_evidence_remains_unknown(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"name": "my-app"}))
    (tmp_path / "src.js").write_text("function run() { return 1; }")
    evidence = build_project_evidence(tmp_path, ["src.js"])

    result = evidence.assess(_result(), "src.js")

    assert result.package_applicabilities[0].status == "unknown"
    assert result.priority == "automatic_vulnerability"


def test_declared_imported_dependency_confirms_applicability(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "my-app", "dependencies": {"axios": "1.0.0"},
    }))
    (tmp_path / "src.js").write_text("const axios = require('axios');")
    evidence = build_project_evidence(tmp_path, ["src.js"])

    result = evidence.assess(_result(), "src.js")

    assert result.package_applicabilities[0].status == "confirmed"
    assert result.package_applicabilities[0].evidence[0].kind == "resolved_dependency"


def test_concrete_different_node_modules_owner_is_conflicting(tmp_path):
    package = tmp_path / "node_modules" / "other"
    package.mkdir(parents=True)
    (package / "package.json").write_text(json.dumps({"name": "other"}))
    (package / "index.js").write_text("function run() { return 1; }")
    evidence = build_project_evidence(tmp_path, ["node_modules/other/index.js"])

    result = evidence.assess(_result(), "node_modules/other/index.js")

    assert result.package_applicabilities[0].status == "conflicting"
    assert result.priority == "automatic_vulnerability"
