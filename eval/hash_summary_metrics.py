"""Pure saved-evidence metrics for the corrected hash-rule report."""
from collections import Counter
from copy import deepcopy
import math
import statistics
from eval.ablation.run_frozen import summarize as frozen_summarize
from eval.metrics import classification_outcome, retrieval_metrics, verification_metrics, llm_metrics

def fraction(count, denominator):
    return {"count": count, "denominator": denominator,
            "rate": count / denominator if denominator else None}

def compute(rows):
    """Keep abstentions separate while including them in all-case denominators."""
    normalized = [dict(r, outcome=classification_outcome(r["expected_status"], r["priority"]),
                       hash_retrieval_hit=r["expected_hash_hit"],
                       exact_hash_retrieval_hit="exact" in r["expected_hash_types"],
                       abstracted_hash_retrieval_hit="abstracted" in r["expected_hash_types"],
                       retrieval_rank=r["expected_aggregate_rank"],
                       ranked_retrieval_rank=r["expected_aggregate_rank"]) for r in rows]
    v = verification_metrics(normalized)
    tp, fn, ap = v["true_positive"], v["false_negative"], v["vulnerable_abstained"]
    fp, tn, an = v["patched_false_positive"], v["patched_true_negative"], v["patched_abstained"]
    assert tp + fn + ap + fp + tn + an == len(rows)
    old = frozen_summarize(rows)
    assert old["positive_cases"] == tp + fn + ap
    assert old["patched_cases"] == fp + tn + an
    assert old["abstained"]["count"] == ap + an
    assert old["patched_false_positive"]["count"] == fp
    assert old["correct_origin_automatic"]["count"] <= tp
    elapsed = sorted(r["elapsed_seconds"] for r in rows)
    return {
        **old, "retrieval": retrieval_metrics(normalized), "verification": v,
        "automatic_vulnerability_recall_all": fraction(tp, tp + fn + ap),
        "conditional_vulnerability_recall": fraction(tp, tp + fn),
        "automatic_vulnerability_precision": fraction(tp, tp + fp),
        "patched_fpr_all": fraction(fp, fp + tn + an),
        "conditional_patched_fpr": fraction(fp, fp + tn),
        "positive_abstention": fraction(ap, tp + fn + ap),
        "patched_abstention": fraction(an, fp + tn + an),
        "binary_tp_without_correct_origin": tp - old["correct_origin_automatic"]["count"],
        "priority_counts": dict(Counter(r["priority"] for r in rows)),
        "mean_seconds": statistics.mean(elapsed),
        "median_seconds": statistics.median(elapsed),
        "p95_seconds_nearest_rank": elapsed[math.ceil(.95 * len(elapsed)) - 1],
        "llm_decision_accuracy": None, "llm_adjusted_vulnerability_recall": None,
        "llm_status": "not_run",
    }

def pct(value):
    return "N/A" if value is None else f"{100 * value:.2f}%"

def cell(value):
    return f"{value['count']}/{value['denominator']} ({pct(value['rate'])})"

def table(headers, rows):
    return "\n".join(["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers),
                      *("| " + " | ".join(map(str, row)) + " |" for row in rows)]) + "\n"

def project(row, opinion=None, aligned=False):
    """Current report-style triage projection; dismissal is NOT a patched verdict."""
    result = {k: deepcopy(v) for k, v in row.items() if k != 'result'}
    if row['priority'] != 'manual_review' or not opinion or opinion['status'] != 'generated':
        return result
    verdict = opinion['llm_verdict']
    if verdict == 'flagged':
        result.update(priority='automatic_vulnerability', abstained=False,
                      correct_origin_automatic=row['expected_status'] == 'flagged' and aligned,
                      wrong_origin_automatic=not aligned,
                      patched_false_positive=row['expected_status'] == 'cleared')
    elif verdict == 'dismissed':
        result.update(priority='none', abstained=False, correct_origin_automatic=False,
                      wrong_origin_automatic=False, patched_false_positive=False)
    return result

def summarize(rows, opinions, bundles):
    projected, llm_rows = [], []
    counts = Counter()
    aligned_decisive = aligned_correct = 0
    for row in rows:
        cid = row['candidate_id']; opinion = opinions.get(cid); bundle = bundles.get(cid, {})
        projected.append(project(row, opinion, bundle.get('expected_origin_matches', False)))
        llm_row = dict(row, outcome=classification_outcome(row['expected_status'], row['priority']))
        if row['abstained']:
            verdict = opinion.get('llm_verdict') if opinion and opinion['status'] == 'generated' else 'unavailable'
            counts[verdict] += 1
            label = 'vulnerable' if row['expected_status'] == 'flagged' else 'patched'
            counts[f'{label}_{verdict}'] += 1
            llm_row['llm_decision'] = {'flagged': 'vulnerable', 'dismissed': 'dismissed'}.get(verdict, 'abstained')
            if verdict == 'flagged':
                counts['confirmed_correct_origin'] += row['expected_status'] == 'flagged' and bundle['expected_origin_matches']
                counts['confirmed_wrong_origin'] += not bundle['expected_origin_matches']
            if verdict in ('flagged', 'dismissed') and bundle.get('expected_origin_matches'):
                aligned_decisive += 1
                aligned_correct += (verdict == 'flagged') == (row['expected_status'] == 'flagged')
        llm_rows.append(llm_row)
    quality = compute(projected)
    positives = [r for r in projected if r['expected_status'] == 'flagged']
    return {'baseline': compute(rows), 'triage_projection': quality, 'llm_counts': dict(counts),
            'report_llm_metrics': llm_metrics(llm_rows),
            'aligned_llm_decision_accuracy': fraction(aligned_correct, aligned_decisive),
            'vulnerable_alert_or_review': fraction(sum(r['priority'] in ('automatic_vulnerability', 'manual_review') for r in positives), len(positives)),
            'automatic_patched_unchanged': fraction(sum(r['expected_status'] == 'cleared' and r['priority'] == 'informational_lineage' for r in rows), sum(r['expected_status'] == 'cleared' for r in rows)),
            'conservative_unresolved': sum(r['abstained'] for r in projected) + counts['dismissed'],
            'scope_note': 'Projection treats primary-advisory dismissal as removing a finding, as current report triage does. This is not a global patched verdict. Conservative unresolved retains dismissals for further boundary review.'}

def pipeline_metrics(rows, results, bundles):
    opinions = {cid: {'status': 'generated' if result['classification'] in {'VULNERABLE': 'flagged', 'PATCHED': 'dismissed', 'INSUFFICIENT_EVIDENCE': 'needs_review'} else 'unavailable',
                      'llm_verdict': {'VULNERABLE': 'flagged', 'PATCHED': 'dismissed', 'INSUFFICIENT_EVIDENCE': 'needs_review'}.get(result['classification'])} for cid, result in results.items()}
    # Legacy report-compatible projection: primary-boundary PATCHED maps to scoped dismissal.
    metrics = summarize(rows, opinions, bundles)
    conservative = {cid: ({'status': 'generated', 'llm_verdict': 'needs_review'}
                         if result['classification'] == 'PATCHED' else opinions[cid]) for cid, result in results.items()}
    metrics['retain_scoped_patched_for_review'] = summarize(rows, conservative, bundles)
    return metrics
