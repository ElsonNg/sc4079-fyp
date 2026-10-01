# Expanded boundary verifier

The scanner now enables the selected `expanded_ast` verifier by default. It uses
the existing retrieval targets and leaves established boundary verdicts intact.
For credible uncertain results, it checks the complete candidate function against
both sides of the same fix. A full-function structural/token gate must pass before
the bounded guard/order/regex recognizers or binding-aware AST correspondence can
resolve a boundary. Edit scoring keeps the 0.90 side threshold and 0.10 margin.

AST correspondence recognizes specific copied-function rewrites, including bound
variable renames, supported TypeScript annotations, and selected control-flow
forms. It preserves free identifiers, property keys, literals, operations and
order. Unsupported syntax, reflection, disagreement and protected conflicts stay
uncertain. The optional dead-noop normalization is disabled.

A verified vulnerable boundary can trigger an alert. A verified patched boundary
is informational only when no credible unresolved alternative requires review.
An exact revision connection can keep an alternative under review even if its
local structural/token gate failed. Missing links or a function mismatch alone
do not dismiss an alternative. Hash routing remains the first detection step.
These decisions describe known fix boundaries; they do not guarantee exploitability
or general safety.

## Controls

- `provtrail scan PATH`: enable expanded verification.
- `provtrail scan PATH --no-expanded-correspondence`: use the earlier S/T/E baseline.
- `provtrail scan PATH --experimental-local-correspondence`: select the earlier
  bounded local verifier instead of the expanded verifier.

The result records `decision_policy` so package-context assessment and cached JSON
preserve the completed decision. The cache schema and configuration fingerprint
invalidate older results. Existing candidate and edit-size limits still apply.

## Validation

Independent AST controls run against both the frozen experimental implementation
and the production implementation. Integration tests cover default/disabled CLI
selection, protected conflicts, hash routing, revision-aware review, JSON roundtrip
and package-context assessment.

Run the saved-evidence integration check with:

```powershell
.venv/Scripts/python.exe -m eval.ablation.check_promoted_verifier
```

This check uses the 1,200 frozen block/function cases and initial retrieval evidence.
It runs production hash lookup, classification, attribution, expanded verification
and final assessment, comparing them with the selected experimental arm. Its
output goes to a fresh `eval/frozen/active-promoted-verifier-v1` directory. It does
not measure fresh retrieval or end-to-end GPU runtime.

The selected study used K5/B10 and block/function regions. Promotion changes the
verifier and reporting policy; retrieval limits and region selection retain their
existing behavior. In particular, the CLI still has its existing verification
budget of 10. A subsequent GPU evaluation must explicitly fix the intended region
and retrieval configuration and use fresh outputs and protocol locks.

### Fresh GPU detector evaluation

```powershell
# Check frozen inputs and print the plan without loading the model or writing outputs.
.\scripts\run_expanded_verifier_gpu.ps1 -Plan

# All 1,200 cases, with three fresh passes for timing and decision stability.
.\scripts\run_expanded_verifier_gpu.ps1
```

The selected K5/B10 configuration means five retrieval hits per candidate region
and up to ten region pairs passed to initial verification. Candidate and reference
retrieval use only block/function regions. This runner explicitly enables the
expanded verifier, keeps the chosen thresholds, and requires CUDA FP32. It loads
the frozen local model and reference index; no hosted model or AI review is called.

To stop, press Ctrl+C. Run the same command to resume from completed case
checkpoints. Keep the code, inputs, output path and repetition count unchanged.
Each completed repetition must match the first repetition's decisions and ranks.

For a separate twelve-case pilot:

```powershell
.\scripts\run_expanded_verifier_gpu.ps1 -SmokeLimit 12 -Repetitions 1
```

The full output is `eval/frozen/active-expanded-e2e-gpu-v1/combined/tables.md`,
with detailed metrics in `summary.json` and full first-pass boundary evidence in
the checkpoints. Pilot outputs use a separate directory. Existing experiment
outputs are preserved. Quality counts each case once; repeats measure timing.
The timer covers detector stages and excludes setup, checkpoint IO, directory
discovery and report rendering.
