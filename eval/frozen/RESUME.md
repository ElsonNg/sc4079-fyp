# Work resumed and completed

The paused generation/validation work was resumed. See [the delivery report](README.md) and [reproduction commands](../ablation/README.md).

- Final cohort: tier2-v2, 60 accepted cases across 10 packages (38 new, 22 historical); 728 quarantined.
- Active frozen experiment: experiment-v2/manifest.json. Experiment v1 is superseded and preserved.
- Runner smoke: smoke-v1, eight tuning cases and two configurations, with direct baseline verification.
- Full ablations remain deferred. No background generation or validation job needs resuming.
- Work is saved in the workspace and has not been committed. Preserve unrelated pre-existing changes.

Do not restart .provtrail/finish_frozen_experiment.py; that obsolete scratch wrapper predates the required source adjudication and revised split.
