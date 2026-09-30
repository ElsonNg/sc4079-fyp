from eval.hash_summary_metrics import compute, pipeline_metrics, summarize


def case(cid, label, priority, correct=False):
    return dict(candidate_id=cid, expected_status=label, priority=priority,
                correct_origin_automatic=correct, wrong_origin_automatic=False,
                patched_false_positive=label == 'cleared' and priority == 'automatic_vulnerability',
                abstained=priority == 'manual_review', elapsed_seconds=1.0,
                hash_path=correct, expected_hash_hit=correct,
                expected_hash_types=['exact'] if correct else [], expected_aggregate_rank=None,
                expected_retrieved=correct, expected_shortlisted=correct, expected_visible=correct)


def test_replay_keeps_abstentions_in_recall_denominator():
    metrics = compute([case('auto', 'flagged', 'automatic_vulnerability', True),
                       case('review', 'flagged', 'manual_review'),
                       case('patched', 'cleared', 'informational_lineage')])
    assert metrics['automatic_vulnerability_recall_all'] == dict(count=1, denominator=2, rate=.5)
    assert metrics['correct_origin_automatic']['count'] == 1
    assert metrics['verification']['patched_true_negative'] == 1


def test_obsolete_llm_dismissal_cannot_override_new_automatic_verdict():
    rows = [case('now-auto', 'flagged', 'automatic_vulnerability', True),
            case('still-review', 'cleared', 'manual_review')]
    opinions = {'now-auto': dict(status='generated', llm_verdict='dismissed')}
    result = summarize(rows, opinions, {})
    assert result['triage_projection']['correct_origin_automatic']['count'] == 1
    assert result['llm_counts'].get('vulnerable_dismissed', 0) == 0
    assert result['llm_counts']['unavailable'] == 1


def test_scoped_patched_projection_retains_other_boundary_review():
    rows = [case('patched-review', 'cleared', 'manual_review')]
    result = pipeline_metrics(rows, {'patched-review': {'classification': 'PATCHED'}}, {})
    assert result['triage_projection']['abstained']['count'] == 0
    assert result['retain_scoped_patched_for_review']['triage_projection']['abstained']['count'] == 1
