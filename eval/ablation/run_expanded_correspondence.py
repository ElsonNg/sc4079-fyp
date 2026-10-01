"""CPU experiment over saved block/function results; no model or new retrieval."""
import argparse
from collections import Counter
from dataclasses import fields
import json
from pathlib import Path
import time

from eval.ablation import run_region_types as runner
from eval.ablation.common import digest, file_hash, read_jsonl, unseal
from eval.ablation.exact_similarity import exact_backend
from eval.ablation.priority_relationships import RevisionRelationships
from eval.ablation.expanded_correspondence import ARMS, recheck
from eval.metrics import expected_retrieval_fields
from provtrail.corpus.integrations.sqlite_store import load_entries
from provtrail.pipeline.controller.region_extraction import extract_corpus_region_pairs
from provtrail.pipeline.detection.config import RegionVerifierConfig
from provtrail.pipeline.models.result import RegionDetectionResult


DEFAULT_SOURCE = runner.ROOT / "eval/frozen/active-block-function-gpu-v1"
DEFAULT_OUTPUT = runner.ROOT / "eval/frozen/active-expanded-correspondence-v1"


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(data, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))


def quality(row, result, expected):
    vulnerable = {s.boundary.fix_boundary_id for s in result.vulnerability_states if s.status == "vulnerable"}
    auto = result.priority == "automatic_vulnerability"
    return dict(row, priority=result.priority, abstained=result.priority == "manual_review",
                correct_origin_automatic=row["expected_status"] == "flagged" and auto and bool(vulnerable & expected),
                wrong_origin_automatic=auto and bool(vulnerable - expected),
                patched_false_positive=row["expected_status"] == "cleared" and auto,
                boundaries=sorted([[s.boundary.fix_boundary_id,s.status,s.abstention_reason] for s in result.vulnerability_states]))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    source, output = args.source.resolve(), args.output.resolve()
    assert not output.is_relative_to(source) and not source.is_relative_to(output)
    assert not output.exists() or not any(output.iterdir()), "Use a fresh output directory"
    lock = source / "study-lock.json"
    study = unseal(json.loads(lock.read_text(encoding="utf-8")))
    assert study["arms"]=={"block_function":["block","function"]} and study["smoke_limit"] is None
    assert all(file_hash(runner.ROOT/name)==sha for name,sha in study["code"].items())
    assert all(file_hash(v["path"])==v["sha256"] for v in study["inputs"].values())
    for repeat in range(1, study["repetitions"]+1):
        marker = unseal(json.loads((runner.pass_dir(source,"block_function",repeat)/"complete.json").read_text(encoding="utf-8")))
        assert marker["study"]==digest(study) and marker["candidate_ids"]==sorted(study["candidate_ids"])
    assignments=json.loads(Path(study["inputs"]["split"]["path"]).read_text(encoding="utf-8"))["assignments"]
    records=[dict(r,split=assignments[r["candidate_id"]]["split"]) for tier in ("tier1","tier2") for r in read_jsonl(study["inputs"][tier]["path"])]
    assert [r["candidate_id"] for r in records]==study["candidate_ids"]
    entries=load_entries(study["inputs"]["reference"]["path"])
    pairs={p.pair_id:p for p in extract_corpus_region_pairs(entries)}
    relationships=RevisionRelationships.from_entries(entries)
    config=RegionVerifierConfig(**{f.name:study["detector"]["verifier"][f.name] for f in fields(RegionVerifierConfig)})
    rows={"baseline":[],**{arm:[] for arm in ARMS}}; changes=[]; traces=[]; checkpoint_hashes={}; seconds=Counter()
    with exact_backend():
        for i, record in enumerate(records,1):
            value=json.loads(runner.checkpoint_path(source,"block_function",1,record["candidate_id"]).read_text(encoding="utf-8"))
            body=unseal(value)
            assert body["identity"]==digest([digest(study),"block_function",1,record])
            old=body["row"]; assert old["expected_status"]==record["expected_status"] and old["candidate_id"]==record["candidate_id"]
            result=RegionDetectionResult.model_validate(old["result"])
            expected=expected_retrieval_fields(record)
            targets={p.fix_boundary_id for p in pairs.values()
                     if (p.origin.fix_commit_sha,p.origin.file_path.replace("\\","/"),p.origin.function_name)==expected[1:]
                     and expected[0] in {a.ghsa_id for a in [p.advisory,*p.advisories]}
                     and p.origin.source_language==record["source_language"]}
            assert targets
            baseline=quality(old,result,targets)
            assert all(baseline[k]==old[k] for k in ("priority","correct_origin_automatic","wrong_origin_automatic","patched_false_positive","abstained","boundaries"))
            rows["baseline"].append(baseline); checkpoint_hashes[record["candidate_id"]]=value["content_sha256"]
            for arm in ARMS:
                start=time.perf_counter()
                updated, evidence=recheck(result,record["candidate_source"],record["source_language"],pairs,relationships,config,mode=arm)
                seconds[arm]+=time.perf_counter()-start
                new=quality(old,updated,targets); rows[arm].append(new)
                if evidence:
                    traces.append(dict(arm=arm,candidate_id=old["candidate_id"],tier=old["tier"],split=old["split"],
                                       expected_status=old["expected_status"],before=old["priority"],after=new["priority"],boundaries=evidence))
                if old["priority"]!=new["priority"] or old["boundaries"]!=new["boundaries"]:
                    changes.append(dict(arm=arm,candidate_id=old["candidate_id"],tier=old["tier"],split=old["split"],
                                        expected_status=old["expected_status"],before=old["priority"],after=new["priority"],
                                        before_boundaries=old["boundaries"],after_boundaries=new["boundaries"],
                                        result=updated.model_dump(mode="json")))
            if old["priority"]=="manual_review": print(f"Checked {i}/{len(records)}: {old['candidate_id']}",flush=True)
    saved=json.loads((source/"combined/summary.json").read_text(encoding="utf-8"))
    assert saved["study"]==digest(study)
    scopes=[]
    for tier in ("combined","tier1","tier2"):
        for split in ("all","tuning","evaluation"):
            for route in ("all","hash","non_hash"):
                def selected(r): return (tier=="combined" or r["tier"]==tier) and (split=="all" or r["split"]==split) and (route=="all" or r["hash_path"]==(route=="hash"))
                base=[r for r in rows["baseline"] if selected(r)]
                if not base: continue
                original=next(s for s in saved["summaries"] if (s["tier"],s["split"],s["route"])==(tier,split,route))
                assert runner.metrics(base)==original["metrics"]
                for arm in ARMS:
                    new=[r for r in rows[arm] if selected(r)]
                    release=[a for a,b in zip(base,new) if a["abstained"] and not b["abstained"]]
                    scopes.append(dict(arm=arm,tier=tier,split=split,route=route,baseline=runner.metrics(base),recheck=runner.metrics(new),
                        patched_released=sum(a["expected_status"]=="cleared" for a in release),
                        vulnerable_released_without_alert=sum(a["expected_status"]=="flagged" and b["priority"]!="automatic_vulnerability" and not b["abstained"] for a,b in zip(base,new)),
                        vulnerable_new_alerts=sum(a["expected_status"]=="flagged" and a["abstained"] and b["priority"]=="automatic_vulnerability" for a,b in zip(base,new)),
                        priority_transitions=dict(Counter(a["priority"]+" -> "+b["priority"] for a,b in zip(base,new) if a["priority"]!=b["priority"]))))
    report=dict(policy="whole_function_binding_ast_correspondence_v1",source=str(source),source_study=digest(study),
                lock_sha256=file_hash(lock),source_summary_sha256=file_hash(source/"combined/summary.json"),
                checkpoint_set_sha256=digest(checkpoint_hashes),code_sha256={p:file_hash(runner.ROOT/p) for p in (
                    "eval/ablation/ast_correspondence.py","eval/ablation/expanded_correspondence.py","eval/ablation/run_expanded_correspondence.py",
                    "eval/ablation/targeted_correspondence.py","eval/ablation/priority_relationships.py","eval/ablation/exact_similarity.py",
                    "src/provtrail/pipeline/controller/local_correspondence.py")},
                scopes=scopes,recheck_cpu_seconds=dict(seconds),
                note="Exploratory CPU verification experiment. Same 1,200 cases and existing boundaries; no retrieval, GPU inference or candidate execution. Original detector timing retained only for baseline comparability, not new detector timing.")
    write(output/"summary.json",report); write(output/"case-changes.json",dict(changes=changes));write(output/"boundary-traces.json",dict(cases=traces))
    lines=["# Expanded whole-function correspondence", "",report["note"],"",
           "All arms first reproduce the previous bounded comparison. Expanded arms add whole-function AST correspondence that preserves lexical binding relationships, operations, control flow, free identifiers, property keys and literals. The noop arm additionally removes the exact statically false void branch. A full-function S/T gate must pass; supported correspondence to one distinct reference side can decide an existing uncertain boundary. Mismatch never rejects a boundary. All original targets and established verdicts remain.",""]
    for split in ("tuning","evaluation","all"):
        lines += [f"## Tier 2 / {split}","","| Check | Correct origin | Patched false alerts | Reviews before -> after | Patched released | Vulnerable newly alerted | Vulnerable released without alert |","|---|---:|---:|---:|---:|---:|---:|"]
        for s in scopes:
            if (s["tier"],s["split"],s["route"])!=("tier2",split,"all"):continue
            m=s["recheck"]; o=m["correct_origin_recall"];f=m["patched_false_alert_rate"]
            lines.append(f"| {s['arm']} | {o['count']}/{o['denominator']} | {f['count']}/{f['denominator']} | {s['baseline']['review_rate']['count']} -> {m['review_rate']['count']} | {s['patched_released']} | {s['vulnerable_new_alerts']} | {s['vulnerable_released_without_alert']} |")
        lines.append("")
    lines += ["## Limits","","Whole-function AST correspondence is an experimental copied-structure check, not general semantic equivalence. It handles specific documented normalizations and abstains on unsupported code. Existing guard/order/regex recognition remains the bounded baseline. Labels select no decisions and no thresholds were tuned here. Whole-function mismatch is not proof of unrelated origin. Retrospective results need independent controls before adoption. No production code or original result files were changed.",""]
    (output/"tables.md").write_bytes(("\n".join(lines)).encode("utf-8"))
    print(f"Results: {output/'tables.md'}",flush=True)


if __name__=="__main__":main()
