"""Independently reconstruct reported metrics and validate every changed verdict."""
import argparse
from collections import Counter
import json
from pathlib import Path

from eval.ablation import run_region_types as runner
from eval.ablation.common import digest, file_hash, read_jsonl, unseal
from eval.ablation.priority_relationships import RevisionRelationships, experimental_priority
from eval.metrics import expected_retrieval_fields
from provtrail.corpus.integrations.sqlite_store import load_entries
from provtrail.pipeline.controller.region_extraction import extract_corpus_region_pairs
from provtrail.pipeline.models.result import RegionDetectionResult


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,default=runner.ROOT/"eval/frozen/active-expanded-correspondence-v1")
    args=parser.parse_args(argv)
    output=args.output.resolve()
    report=read(output/"summary.json")
    assert all(file_hash(runner.ROOT/path)==sha for path,sha in report["code_sha256"].items())
    source=Path(report["source"])
    study=unseal(read(source/"study-lock.json"))
    assert digest(study)==report["source_study"]
    assert file_hash(source/"study-lock.json")==report["lock_sha256"]
    assert file_hash(source/"combined/summary.json")==report["source_summary_sha256"]
    assert all(file_hash(value["path"])==value["sha256"] for value in study["inputs"].values())
    assert all(file_hash(runner.ROOT/name)==sha for name,sha in study["code"].items())
    assignments=read(study["inputs"]["split"]["path"])["assignments"]
    records=[dict(r,split=assignments[r["candidate_id"]]["split"]) for tier in ("tier1","tier2")
             for r in read_jsonl(study["inputs"][tier]["path"])]
    assert [r["candidate_id"] for r in records]==study["candidate_ids"]
    pairs=extract_corpus_region_pairs(load_entries(study["inputs"]["reference"]["path"]))
    graph=RevisionRelationships.from_entries(load_entries(study["inputs"]["reference"]["path"]))
    changes={}; rows={"baseline":[]}; checkpoint_hashes={}
    for item in read(output/"case-changes.json")["changes"]:
        key=(item["arm"],item["candidate_id"])
        assert key not in changes
        changes[key]=item
    arms=sorted({s["arm"] for s in report["scopes"]})
    rows.update({a:[] for a in arms})
    witness=Counter(); exceptions=Counter()
    traces={(t["arm"],t["candidate_id"]):t for t in read(output/"boundary-traces.json")["cases"]}
    for record in records:
        value=read(runner.checkpoint_path(source,"block_function",1,record["candidate_id"]))
        body=unseal(value)
        assert body["identity"]==digest([digest(study),"block_function",1,record])
        old=body["row"]
        assert (old["candidate_id"],old["expected_status"],old["split"])==(
            record["candidate_id"],record["expected_status"],record["split"])
        original=RegionDetectionResult.model_validate(old["result"])
        checkpoint_hashes[record["candidate_id"]]=value["content_sha256"]
        expected=expected_retrieval_fields(record)
        targets={p.fix_boundary_id for p in pairs if
                 (p.origin.fix_commit_sha,p.origin.file_path.replace("\\","/"),p.origin.function_name)==expected[1:]
                 and p.origin.source_language==record["source_language"]
                 and expected[0] in {a.ghsa_id for a in [p.advisory,*p.advisories]}}
        assert targets
        rows["baseline"].append(old)
        for arm in arms:
            change=changes.get((arm,record["candidate_id"]))
            result=RegionDetectionResult.model_validate(change["result"]) if change else original
            assert [s.boundary for s in result.vulnerability_states]==[s.boundary for s in original.vulnerability_states]
            assert all(a.model_dump()==b.model_dump() for a,b in zip(original.vulnerability_states,result.vulnerability_states)
                       if a.status!="uncertain")
            assert result.priority==experimental_priority(result,graph)
            if original.hash_matches or original.priority!="manual_review":
                assert result.model_dump(mode="json")==original.model_dump(mode="json")
            if record["candidate_id"] in {"L034","LN018"}:
                assert result.priority=="manual_review"
                exceptions[(arm,record["candidate_id"])]+=1
            vulnerable={s.boundary.fix_boundary_id for s in result.vulnerability_states if s.status=="vulnerable"}
            auto=result.priority=="automatic_vulnerability"
            new=dict(old,priority=result.priority,abstained=result.priority=="manual_review",
                correct_origin_automatic=record["expected_status"]=="flagged" and auto and bool(vulnerable&targets),
                wrong_origin_automatic=auto and bool(vulnerable-targets),
                patched_false_positive=record["expected_status"]=="cleared" and auto,
                boundaries=sorted([[s.boundary.fix_boundary_id,s.status,s.abstention_reason] for s in result.vulnerability_states]))
            if change:
                assert (change["before"],change["after"],change["before_boundaries"],change["after_boundaries"])==(
                    original.priority,result.priority,old["boundaries"],new["boundaries"])
                assert change["split"]==record["split"] and change["expected_status"]==record["expected_status"]
            if original.priority!=result.priority:
                assert original.priority=="manual_review"
                assert result.priority in {"informational_lineage","automatic_vulnerability"}
                assert record["expected_status"]=="cleared" or new["correct_origin_automatic"]
            if record["expected_status"]=="cleared":
                assert new["patched_false_positive"]==old["patched_false_positive"]
            if (arm,record["candidate_id"]) in traces:
                by_id={s.boundary.fix_boundary_id:s for s in result.vulnerability_states}
                for trace in traces[arm,record["candidate_id"]]["boundaries"]:
                    answer=trace.get("expanded_ast") or {}
                    if answer.get("status") in {"patched","vulnerable"}:
                        assert trace["full_function_gate"] and trace["before_expanded"]=="uncertain"
                        assert by_id[trace["boundary"]].status==answer["status"]
                        witness[(arm,answer["status"])]+=1
            rows[arm].append(new)
    assert digest(checkpoint_hashes)==report["checkpoint_set_sha256"]
    assert len(exceptions)==2*len(arms)
    previous=read(runner.ROOT/"eval/frozen/active-targeted-correspondence-v1/summary.json")
    for scope in report["scopes"]:
        def selected(r):
            return (scope["tier"]=="combined" or r["tier"]==scope["tier"]) and (
                scope["split"]=="all" or r["split"]==scope["split"]) and (
                scope["route"]=="all" or r["hash_path"]==(scope["route"]=="hash"))
        base=[r for r in rows["baseline"] if selected(r)]
        new=[r for r in rows[scope["arm"]] if selected(r)]
        assert runner.metrics(base)==scope["baseline"] and runner.metrics(new)==scope["recheck"]
        release=[(a,b) for a,b in zip(base,new) if a["abstained"] and not b["abstained"]]
        assert scope["patched_released"]==sum(a["expected_status"]=="cleared" for a,b in release)
        assert scope["vulnerable_new_alerts"]==sum(a["expected_status"]=="flagged" and b["priority"]=="automatic_vulnerability" for a,b in release)
        assert scope["vulnerable_released_without_alert"]==sum(a["expected_status"]=="flagged" and b["priority"]!="automatic_vulnerability" for a,b in release)==0
        assert scope["priority_transitions"]==dict(Counter(a["priority"]+" -> "+b["priority"] for a,b in zip(base,new) if a["priority"]!=b["priority"]))
        if scope["arm"]=="bounded_baseline":
            old=next(s for s in previous["scopes"] if s["arm"]=="direct_plus_bounded" and
                     (s["tier"],s["split"],s["route"])==(scope["tier"],scope["split"],scope["route"]))
            assert old["recheck"]==scope["recheck"]
    audit=dict(cases=len(records),scopes=len(report["scopes"]),status="passed",
        code_sha256={"eval/ablation/audit_expanded_correspondence.py":file_hash(__file__)},
        report_sha256={p:file_hash(output/p) for p in ("summary.json","case-changes.json","boundary-traces.json","tables.md")},
        decisive_ast_boundaries={str(k):v for k,v in witness.items()},
        checks=["checkpoint seals and identities", "all metrics independently reconstructed", "previous bounded baseline reproduced",
                "same target boundaries and established verdicts", "hashes and initially non-review results preserved",
                "L034 and LN018 retained", "no new false alerts or vulnerable releases without alerts"])
    (output/"audit.json").write_bytes((json.dumps(audit,indent=2)+"\n").encode("utf-8"))
    print(json.dumps(audit,indent=2))


if __name__=="__main__":main()
