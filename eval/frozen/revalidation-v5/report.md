# Continued corpus validation

New security-boundary tests for selected origins; other evidence inherited from verified prior records. Automated extracted-function validation with explicit stubs, not human vetting or full-package exploit testing. Active experiment freeze and original fixtures remain unchanged. Requested clone categories remain unconfirmed unless mechanically established.

Rechecked 70 cases across 13 reference origins. Newly supported cases: 65.

| Tier | Total candidates | Supported | Failed checks | Unresolved |
|---|---:|---:|---:|---:|
| tier1 | 600 | 220 | 0 | 380 |
| tier2 | 788 | 246 | 52 | 490 |

Tier 2 pair/duplicate-eligible subset: 202 cases (101 pairs), 16 packages.
Unresolved cases span 213 advisory/fix/function origins. The complete candidate pools remain 600 and 788.

| Tier | Previous outcome | New outcome | Cases |
|---|---|---|---:|
| tier1 | needs_review | validated_executable | 26 |
| tier2 | needs_review | failed_behaviour | 5 |
| tier2 | needs_review | validated_executable | 39 |

The new harnesses require an explicit security witness: it must be absent in the vulnerable original and present in the patched original. The candidate must match its labelled original across that witness and all controls. Mere output differences do not establish the security label.
Existing bound negative candidate reviews remain unresolved even if the new bounded tests pass. A test that contradicts a previous admission is recorded as a failure; previous records are preserved.
Executable observations include explicit helper/stub assumptions. They are not proof of complete semantic equivalence or package exploitability. No clone Type 3/4 confirmation is inferred from a behavioural pass.

See changes.jsonl for transitions, validation.jsonl for every case, checks.jsonl for new executable evidence, and followup.jsonl for remaining work.

```powershell
.venv/Scripts/python.exe -m eval.tier2.extend_validation --previous eval/frozen/revalidation-v4 --suite eval.tier2.permission_checks --output eval/frozen/revalidation-v5 --resume
```
For a fresh run use another empty output directory and omit --resume. The prior report, original inputs, code, Node and parser versions must still match their sealed records.
