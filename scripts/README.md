# Project scripts

Evaluation implementations live under `eval/`. Run them from the repository root
after installing the project with `python -m pip install -r requirements.txt`:

```powershell
python -m eval.tier1.build_tier1_targets
python -m eval.tier1.validate_tier1_releases
python -m eval.tier2.validate_llm_transformed_subset --help
python -m eval.comparison_benchmark.run_tool_comparison --help
```

See [evaluation commands](../eval/README.md), [ablation studies](../eval/ablation/README.md)
and [scanner comparisons](../eval/comparison_benchmark/README.md) for input paths
and study-specific PowerShell runners. The former forwarding Python scripts were
removed; use the corresponding `eval` module instead.

The former `rebuild_corpus.py` script is superseded by the snapshot-verified CLI:

```powershell
provtrail corpus build --package axios --package express
provtrail corpus build --all
provtrail corpus index --device cpu
```

Choose either selected packages or `--all`. A successful build replaces the active
corpus; use `--append` to merge additional packages. See the
[corpus setup guide](../README.md#2-prepare-the-reference-corpus) for details.

Remaining Python scripts support the contextual Semgrep batch, the paired jscpd
probe, and local report generation. Frozen manifests and validation evidence are
retained for reproducibility.
