import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from eval.ablation.common import digest, read_jsonl, seal, write_json
from eval.ablation.freeze import baseline, grouped_split, verify_manifest
from eval.ablation.run_frozen import checkpoint_key, expand_sweep, measure, nondominated, read_checkpoint, summarize
from eval.tier2 import cohort
from eval.tier2.source_review import equivalence
from provtrail.corpus.models.corpus import CorpusEntry


def entry(ghsa="A", commit="one", function="f", package="axios", aliases=None):
    return CorpusEntry(ghsa_id=ghsa, package_name=package, ecosystem="npm", repo="org/repo",
        fix_commit_sha=commit, file_path="file.js", function_name=function,
        vulnerable_function=f"function {function}(x) {{ return x.{commit}; }}",
        patched_function=f"function {function}(x) {{ if (x) return x.{commit}; }}",
        diagnostic_lines=[{"kind": "removed", "text": "return x.one;"}, {"kind": "added", "text": "if (x) return x.one;"}],
        advisory_aliases=aliases or [])


def record(e, cid, side="flagged", kind="type_3", source=None):
    r = cohort._base_record(e, source or f"function {cid}(x) {{ return x.one; }}", kind)
    r.update(candidate_id=cid, expected_status=side, tier="tier2", requested_clone_type=kind)
    return r


def review(r, accepted=True):
    return {"candidate_id": r["candidate_id"], "accepted": accepted, "assessment": {"classification": "type_3"}}


def test_selection_diversity_determinism_distinct_fix_origins():
    entries = [entry("A", "a", "a"), entry("A", "a", "b"), entry("B", "b", "a"), entry("C", "a", "a")]
    chosen = cohort.select_origins(entries, 2)
    assert [e.advisory.ghsa_id for e in chosen] == ["A", "B"]
    assert cohort.select_origins(list(reversed(entries)), 2) == chosen
    assert len(cohort.select_origins(entries, 10)) == 3


def test_pair_acceptance_quarantine_and_duplicates():
    e = entry()
    a, b = record(e, "a"), record(e, "b", "cleared")
    assert len(cohort.admit([a,b], [review(a),review(b)])[0]) == 2
    good, bad, validation = cohort.admit([a,b], [review(a),review(b,False)])
    assert not good and len(bad) == 2
    assert "pair_quarantined" in validation[0]["reasons"]
    assert not cohort.admit([a], [review(a)])[0]
    c = record(entry("B", "b"), "c", source=a["candidate_source"])
    good, _, validation = cohort.admit([a,b,c], [review(a),review(b),review(c)])
    assert not good
    assert any("duplicate_candidate_source" in r["reasons"] for r in validation)


def test_declared_language_and_identity_screening():
    e = entry()
    r = record(e,"a",source="function f(x: string) { return x; }")
    assert "declared_language_parse_error" in cohort.screen(r,e)[0]
    r["candidate_source_sha256"] = "bad"
    assert "candidate_source_identity_mismatch" in cohort.screen(r,e)[0]


def test_generation_resume_and_three_attempt_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(cohort,"model_identity",lambda *a: {"name":"fake", "digest":"digest", "details":{}})
    calls = []
    def generate(*a):
        calls.append(a)
        return json.dumps({"code": "function invalid("})
    monkeypatch.setattr(cohort,"chat",generate)
    cohort.generate([entry()],tmp_path,host="local",model="fake")
    assert len(calls) == 12  # four tasks, three actual requests each
    cohort.generate([entry()],tmp_path,host="local",model="fake")
    assert len(calls) == 12
    assert len(cohort.load_attempts(tmp_path / "attempts.jsonl")) == 12
    with pytest.raises(ValueError,match="mismatch"):
        cohort.generate([entry(commit="changed")],tmp_path,host="local",model="fake")


def test_successful_generation_resume(tmp_path, monkeypatch):
    monkeypatch.setattr(cohort,"model_identity",lambda *a: {"name":"fake", "digest":"digest", "details":{}})
    calls = []
    def generate(*a):
        calls.append(a)
        return json.dumps({"code": "function renamed(x) { return x.one; }"})
    monkeypatch.setattr(cohort,"chat",generate)
    rows = cohort.generate([entry()],tmp_path,host="local",model="fake")
    assert len(rows) == 4
    cohort.generate([entry()],tmp_path,host="local",model="fake")
    assert len(calls) == 4
    assert rows[0]["generator"]["digest"] == "digest"
    assert rows[0]["clone_type_status"] == "requested_unconfirmed"


def test_group_isolation_aliases_shared_fixes_duplicates_transitive():
    a = entry("A", "a", aliases=[{"ghsa_id":"B"}])
    b = entry("B", "b")
    c = entry("C", "b", "g")
    d = entry("D", "d")
    other = [entry(str(i),"commit"+str(i)) for i in range(10)]
    entries = [a,b,c,d,*other]
    rows = [record(e,str(i)) for i,e in enumerate(entries)]
    rows[0]["tier"] = "tier1"
    rows[3]["candidate_source"] = rows[2]["candidate_source"]
    first = grouped_split(rows,entries)
    again = grouped_split(list(reversed(rows)),list(reversed(entries)))
    assert first == again
    assert len({first["assignments"][str(i)]["group"] for i in range(4)}) == 1
    assert set(first["actual_counts"]) == {"tuning","evaluation"}


def test_missing_expected_origin_fails_split():
    with pytest.raises(ValueError,match="Missing expected"):
        grouped_split([record(entry(),"a")],[])


def test_sparse_packages_still_receive_a_useful_tier_tuning_partition():
    entries = [entry(str(i), 'fix'+str(i), package='package'+str(i)) for i in range(10)]
    rows = [record(e, str(i)) for i, e in enumerate(entries)]
    split = grouped_split(rows, entries)
    assert split['actual_counts']['tuning'] == 3
    assert split == grouped_split(list(reversed(rows)), list(reversed(entries)))


def test_manifest_byte_and_seal_mismatch(tmp_path):
    data = tmp_path / "fixture.jsonl"
    data.write_text("original")
    m = {"artifacts":{"fixtures":{"path":str(data),"sha256":digest("original")}},
         "code_files":[],"embedding_model":{"files":[]},"dependencies":{}}
    path = tmp_path / "manifest.json"
    write_json(path,seal(m))
    assert verify_manifest(path)["artifacts"] == m["artifacts"]
    data.write_text("changed")
    with pytest.raises(ValueError,match="artifact mismatch"):
        verify_manifest(path)
    write_json(path,dict(seal(m),dependencies={"bad":"1"}))
    with pytest.raises(ValueError,match="seal mismatch"):
        verify_manifest(path)


def test_sweep_31_deduplicated_configs_and_independent_thresholds():
    spec = json.loads(Path("eval/ablation/sweep.json").read_text())
    configs = expand_sweep(spec)
    assert len(configs) == 31
    assert len({digest(c["configuration"]) for c in configs}) == 31
    assert configs[0]["configuration"] == baseline()
    for c in configs:
        config = c["configuration"]
        if "structure_independent" in c["experiments"]:
            assert config["verifier"]["minimum_token_score"] == .7
        if "token_independent" in c["experiments"]:
            assert config["verifier"]["minimum_structure_score"] == .7
    with pytest.raises(ValueError,match="inactive"):
        expand_sweep({"experiments":[{"name":"bad","grid":{"minimum_supporting_regions":[3]}}]})


@pytest.mark.parametrize("grid", [{"retrieval_top_k":[0]}, {"retrieval_top_k":[1.5]}, {"minimum_edit_margin":[2]}, {"minimum_token_score":[]}])
def test_invalid_sweep_values(grid):
    with pytest.raises(ValueError):
        expand_sweep({"experiments":[{"name":"bad","grid":grid}]})


def test_checkpoint_requires_entire_candidate_config_manifest_and_seal(tmp_path):
    manifest = {"content_sha256":"first"}
    r = record(entry(),"a")
    key = checkpoint_key(manifest,baseline(),r)
    path = tmp_path / "checkpoint.json"
    write_json(path,seal({"checkpoint_key":key,"row":{"priority":"none"}}))
    assert read_checkpoint(path,key)["priority"] == "none"
    for m,c,rec in [(dict(content_sha256="second"),baseline(),r),
                    (manifest,dict(baseline(),retrieval_top_k=1),r),
                    (manifest,baseline(),dict(r,candidate_source="changed"))]:
        with pytest.raises(ValueError,match="mismatch"):
            read_checkpoint(path,checkpoint_key(m,c,rec))


def test_denominators_include_abstentions_and_separate_hash_paths():
    def row(label,abstain=False,correct=False,fp=False,hashed=False):
        return dict(expected_status=label,abstained=abstain,correct_origin_automatic=correct,
            patched_false_positive=fp,hash_path=hashed,expected_retrieved=hashed,expected_shortlisted=hashed,
            expected_visible=hashed,wrong_origin_automatic=False,elapsed_seconds=.2)
    rows = [row("flagged",correct=True,hashed=True),row("flagged",abstain=True),row("cleared",fp=True),row("cleared",abstain=True)]
    s = summarize(rows)
    assert s["correct_origin_automatic"] == {"count":1,"denominator":2,"rate":.5}
    assert s["conditional_correct_origin_recall_excluding_abstentions"]["rate"] == 1
    assert s["patched_false_positive_over_all_labelled"]["rate"] == .25
    assert s["hash_retrieval"]["denominator"] == 1
    assert s["non_hash_retrieval"]["denominator"] == 3
    assert summarize([])["patched_false_positive"]["rate"] is None


def test_nondominated_does_not_pick_winner():
    def s(cid,tp,fp,time):
        return dict(configuration_id=cid,correct_origin_automatic={"count":tp},patched_false_positive={"count":fp},
                    wrong_origin_automatic={"count":0},abstained={"count":0},runtime_seconds=time)
    assert nondominated([s("a",5,1,1),s("b",6,2,1),s("c",4,2,2)]) == ["a","b"]


def test_mechanical_review_rejects_capture_and_security_changes():
    assert equivalence("function f(x) { return x.a; }", "function f(y) { return y.a; }", "javascript")["preserved"]
    for before, after in [
        ("function f(x) { return x.a; }", "function f(y) { return y.b; }"),
        ("function f(x) { return x.a; }", "function f(y) { if (y) return y.a; }"),
        ("function f(x) { return x+y; }", "function f(y) { return y+y; }"),
        ("function f() { use(x); return function g(x) {return x;} }", "function f() { use(y); return function g(y) {return y;} }"),
        ("function f() { use(x); if(ok) {let x=1; use(x);} }", "function f() { use(y); if(ok) {let y=1; use(y);} }"),
        ("function f(x) { return {x}; }", "function f(y) { return {y}; }"),
        ("function f(x) { return eval('x'); }", "function f(y) { return eval('x'); }"),
    ]:
        assert not equivalence(before, after, "javascript")["preserved"]


def test_pending_generation_request_consumes_attempt(tmp_path, monkeypatch):
    from eval.ablation.common import append_jsonl, entry_identity
    e = entry()
    task = digest([entry_identity(e), "type_3", "vulnerable"])
    for n in range(1,4):
        append_jsonl(tmp_path / "attempts.jsonl", {"task":task,"attempt":n,"status":"started"})
    monkeypatch.setattr(cohort,"model_identity",lambda *a: {"name":"fake", "digest":"digest", "details":{}})
    calls = []
    def generate(*a):
        calls.append(a)
        return json.dumps({"code":"function renamed(x) { return x.one; }"})
    monkeypatch.setattr(cohort,"chat",generate)
    cohort.generate([e],tmp_path,host="local",model="fake")
    assert len(calls) == 3  # exhausted interrupted task was not sent again


def test_executable_qs_litmus_distinguishes_sources_and_rejects_flipped_label():
    from eval.tier2.behaviour import check
    e = entry(package="qs",function="parseObject")
    e.vulnerable_function = "function(chain, val) { const obj = {}; obj[chain[0]] = val; return obj; }"
    e.patched_function = "function(chain, val) { const obj = {}; if (chain[0] !== '__proto__') obj[chain[0]] = val; return obj; }"
    positive = record(e,"q",source=e.vulnerable_function)
    assert check(positive,e)["accepted"]
    assert not check(dict(positive,expected_status="cleared"),e)["accepted"]


def test_metrics_require_expected_fix_not_just_same_lineage():
    e = entry()
    r = record(e,"a")
    pair = SimpleNamespace(origin=e.origin,advisory=e.advisory,advisories=[],fix_boundary_id="expected",lineage_id="shared")
    result = SimpleNamespace(priority="automatic_vulnerability",hash_matches=[],aggregates=[],lineages=[SimpleNamespace(lineage_id="shared")],
        vulnerability_states=[SimpleNamespace(status="vulnerable",boundary=SimpleNamespace(fix_boundary_id="other"))],
        model_dump=lambda **kw: {})
    m = measure(r,result,{"p":pair},[],.1)
    assert not m["correct_origin_automatic"] and m["wrong_origin_automatic"]
    assert not m["expected_visible"] and m["expected_lineage_visible"]
    result.vulnerability_states[0].boundary.fix_boundary_id = "expected"
    assert measure(r,result,{"p":pair},[],.1)["correct_origin_automatic"]
    assert measure(r,result,{"p":pair},[],.1)["expected_visible"]
    assert not measure(dict(r,expected_status="cleared"),result,{"p":pair},[],.1)["correct_origin_automatic"]


def test_normalized_duplicates_keep_comments_out_and_identifiers_in():
    from eval.ablation.common import source_key
    assert source_key("function f(x){return x;}","javascript") == source_key("function f(x) { /* c */ return x; }", "javascript")
    assert source_key("function f(x){return x;}","javascript") != source_key("function f(y){return y;}", "javascript")


def test_evaluation_baseline_does_not_change_scanner_defaults():
    from provtrail.pipeline.detection.config import RegionDetectorConfig
    assert RegionDetectorConfig().max_verification_candidates == 5
    assert baseline()["max_verification_candidates"] == 10


def test_review_resume_matches_candidate_and_records_actual_reviewer(tmp_path, monkeypatch):
    e = entry()
    rows = [record(e,"a"),record(e,"b","cleared")]
    monkeypatch.setattr(cohort,"model_identity",lambda *a: {"name":"reviewer", "digest":"v1", "details":{}})
    monkeypatch.setattr(cohort,"behaviour_check",lambda *a: None)
    monkeypatch.setattr(cohort,"review_record",lambda *a: {"accepted":False})
    calls = []
    def chat(*args):
        calls.append(args)
        side = json.loads(args[2][1]["content"])["side"]
        return json.dumps({"security_delta_supported":True,"preserves_requested_side":True,"candidate_security_side":side,
                           "classification":"type_3","security_change":"Adds null guard",
                           "vulnerable_quote":"return x.one;","patched_quote":"if (x)",
                           "candidate_quote":"return x.one;","preservation_reason":"guard reviewed"})
    monkeypatch.setattr(cohort,"chat",chat)
    reviews = cohort.review(rows,[e],tmp_path,host="local",model="reviewer")
    assert len(calls) == 2 and all(r["accepted"] for r in reviews)
    assert reviews[0]["reviewer"]["digest"] == "v1"
    assert reviews[0]["reviewer_type"] == "automated"
    cohort.review(rows,[e],tmp_path,host="local",model="reviewer")
    assert len(calls) == 2
    rows[0] = dict(rows[0],candidate_source="function c(x) { return x.one; }",candidate_source_sha256=digest("function c(x) { return x.one; }"))
    cohort.review(rows,[e],tmp_path,host="local",model="reviewer")
    assert len(calls) == 3


def test_adjudication_requires_bound_source_review_and_preserves_pair_rejection():
    from eval.tier2.adjudicate import finalize, origin_key
    e = entry()
    a = record(e, 'a', source='function f(x) { /* transform */ return x.one; }')
    b = record(e, 'b', 'cleared', source='function f(x) { /* transform */ if (x) return x.one; }')
    rows = [a, b]
    reviews = [dict(review(r), review_key=r['candidate_id'], method='model_source_and_patch_review',
                    mechanical_source_review={'accepted': False}) for r in rows]
    _, _, validation = cohort.admit(rows, reviews)
    decision = dict(origin_key=origin_key(a), reviewer_type='automated', reviewer='test-reviewer',
        reason='Adds a visible null guard.', vulnerable_quote='return x.one;', patched_quote='if (x)', supported=True,
        candidate_reviews=[dict(candidate_id=r['candidate_id'], candidate_sha256=digest(r['candidate_source']),
            accepted=True, preservation_reason='Only a comment is added; guard and return are unchanged.') for r in rows])
    with pytest.raises(ValueError, match='Missing explicit'):
        finalize(rows, validation, [])
    with pytest.raises(ValueError, match='quotation/source mismatch'):
        finalize(rows, validation, [dict(decision, patched_quote='invented guard')])
    with pytest.raises(ValueError, match='Missing bound candidate preservation'):
        finalize(rows, validation, [dict(decision, candidate_reviews=[])])
    accepted, _, _, _ = finalize(rows, validation, [decision])
    assert len(accepted) == 2
    assert all(r['reviewed_clone_type'] == 'unconfirmed' for r in accepted)
    assert all(r['proposed_clone_type'] == 'type_3' for r in accepted)
    with pytest.raises(ValueError, match='Supporting helper context'):
        finalize(rows, validation, [dict(decision, supporting_reference_context=[e.model_dump()])])
    assert len(finalize(rows, validation, [dict(decision, supporting_reference_context=[e.model_dump()])], [e])[0]) == 2
    accepted, quarantine, final_validation, _ = finalize(rows, validation, [dict(decision, supported=False)])
    assert not accepted and len(quarantine) == 2
    assert all('security_delta_not_supported_in_extracted_context' in v['reasons'] for v in final_validation)
    validation[0]['accepted'] = False
    assert not finalize(rows, validation, [decision])[0]  # never promote a prior rejection


def test_literal_screen_detects_changed_regex_escape_and_semantic_constants():
    from eval.tier2.adjudicate import literals
    before = r'function f(x) { return /\bbase64$/i.test(x); }'
    after = 'function g(y) { return /\bbase64$/i.test(y); }'  # literal backspace, not regex boundary
    assert literals(before, 'javascript') != literals(after, 'javascript')
    assert literals(before, 'javascript') == literals(before.replace('x', 'renamed'), 'javascript')
    assert literals('const x = 20;', 'javascript') != literals('const x = 200;', 'javascript')


def test_smoke_selection_covers_available_strata_deterministically(monkeypatch):
    from eval.ablation.run_frozen import smoke_select
    from provtrail.pipeline.controller import hashing
    monkeypatch.setattr(hashing, 'lookup', lambda source, index, filename: [SimpleNamespace(origin=SimpleNamespace(source_language='javascript'))] if source == 'hash' else [])
    rows = [dict(candidate_id=str(i), expected_status=label, source_language=language, tier=tier,
                 requested_clone_type=kind, candidate_source=source) for i, (label, language, tier, kind, source) in enumerate([
        ('flagged', 'javascript', 'tier1', None, 'hash'),
        ('cleared', 'typescript', 'tier2', 'type_3', 'not hash'),
        ('flagged', 'javascript', 'tier2', 'type_4', 'not hash'),
    ])]
    detector = SimpleNamespace(hash_index={})
    first = smoke_select(rows, detector, 3)
    assert first == smoke_select(list(reversed(rows)), detector, 3)
    assert {'path:hash', 'path:non_hash', 'requested:type_3', 'requested:type_4', 'language:typescript'} <= set(first[1])
    with pytest.raises(ValueError, match='cannot cover'):
        smoke_select(rows, detector, 1)


def test_frozen_loader_rejects_missing_index_and_unsearchable_expected_origin(monkeypatch):
    from eval.ablation import freeze
    from provtrail.pipeline.controller import region_extraction, region_retrieval
    e = entry()
    pair = SimpleNamespace(pair_id='p', origin=e.origin, advisory=e.advisory, advisories=[])
    monkeypatch.setattr(freeze, 'load_entries', lambda path: [e])
    monkeypatch.setattr(region_extraction, 'extract_corpus_region_pairs', lambda entries: [pair])
    manifest = {'artifacts': {'reference': {'path': 'unused.db'}, 'index_metadata': {'path': 'index/unused.json'}},
                'expected_origins': [['missing', 'one', 'file.js', 'f']]}
    monkeypatch.setattr(region_retrieval, 'load_region_index', lambda *a, **kw: None)
    with pytest.raises(ValueError, match='rebuilding forbidden'):
        freeze.load_frozen_detector(manifest, baseline())
    monkeypatch.setattr(region_retrieval, 'load_region_index', lambda *a, **kw: SimpleNamespace(
        index=SimpleNamespace(ntotal=1), indexed_pair_ids=['p'], indexed_sides=['vulnerable']))
    with pytest.raises(ValueError, match='absent from searchable index'):
        freeze.load_frozen_detector(manifest, baseline())
