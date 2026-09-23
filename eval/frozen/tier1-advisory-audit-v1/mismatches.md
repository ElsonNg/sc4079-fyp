# Tier 1 release-source mismatches

All 18 release target hashes differ from the fix-commit function. Sixteen have hash-bound historical release source with the advisory-specific before/after change; two Multer callbacks are incompatible.

| Candidate | Package/version | Side | Advisory | Verdict | Target hash | Reference hash |
|---|---|---|---|---|---|---|
| T1-04543711f28d40141244 | ws 3.3.1 | patched | GHSA-5v72-xg48-5rpm | valid_release_specific_reference | `fe7e44825fc9` | `1d2cd8e2b2ff` |
| T1-065d7b498750f264e4b0 | multer 2.0.1 | vulnerable | GHSA-fjgf-rc76-4x9p | excluded_incompatible_release_pair | `6cf571df2c1f` | `357ea11545ea` |
| T1-0e50f38dc863b0180a16 | ws 1.1.5 | patched | GHSA-5v72-xg48-5rpm | valid_release_specific_reference | `e3c38d49a4f2` | `84680a353caf` |
| T1-1ac05b887fd6c36a69d2 | parse-server 9.7.0-alpha.8 | vulnerable | GHSA-m983-v2ff-wq65 | valid_release_specific_reference | `fb15851d7f0a` | `59130e349730` |
| T1-22000a720d2f75bd8541 | better-auth 1.6.10 | vulnerable | GHSA-fmh4-wcc4-5jm3 | valid_release_specific_reference | `69bab8905ba8` | `975258356832` |
| T1-2981cc5bed0db2ec29af | parse-server 9.7.0-alpha.9 | patched | GHSA-m983-v2ff-wq65 | valid_release_specific_reference | `a6c31d003607` | `8afbd15237a7` |
| T1-4222193fb3ec79886194 | ws 1.1.4 | vulnerable | GHSA-5v72-xg48-5rpm | valid_release_specific_reference | `2779f11defb7` | `65a910b2ce33` |
| T1-47347f85f2bd6eb900b8 | parse-server 8.6.53 | patched | GHSA-fph2-r4qg-9576 | valid_release_specific_reference | `fb15851d7f0a` | `59130e349730` |
| T1-473609512c486f65a1ec | electron 1.7.12 | vulnerable | GHSA-8xwg-wv7v-4vqp | valid_release_specific_reference | `745b1a9c556b` | `2d7c4ff5380c` |
| T1-52521fef1a550156c2f2 | parse-server 8.6.64 | vulnerable | GHSA-m983-v2ff-wq65 | valid_release_specific_reference | `fb15851d7f0a` | `59130e349730` |
| T1-6f8b392ca2d070ef1653 | better-auth 1.6.11 | patched | GHSA-fmh4-wcc4-5jm3 | valid_release_specific_reference | `a642fa321c09` | `37b87f482e78` |
| T1-77ba711ed46cb8e10664 | parse-server 9.6.0-alpha.41 | vulnerable | GHSA-fph2-r4qg-9576 | valid_release_specific_reference | `3b90c8cc82fa` | `d6a8da38fb33` |
| T1-7a08c4ddd679f90959fe | multer 2.0.2 | patched | GHSA-fjgf-rc76-4x9p | excluded_incompatible_release_pair | `92a6448d947a` | `8c4e161c8de3` |
| T1-7fcb0956ba0ccb61274e | parse-server 8.6.65 | patched | GHSA-m983-v2ff-wq65 | valid_release_specific_reference | `a6c31d003607` | `8afbd15237a7` |
| T1-8aacb03db5bfda571576 | ws 3.3.0 | vulnerable | GHSA-5v72-xg48-5rpm | valid_release_specific_reference | `251daf3686fb` | `d19985b55a07` |
| T1-9ec7ee750fdb6da5a3cf | electron 1.7.13 | patched | GHSA-8xwg-wv7v-4vqp | valid_release_specific_reference | `8eec5e4e8d49` | `a86d6877f1a0` |
| T1-a4f1a7e1816b241c233f | parse-server 8.6.52 | vulnerable | GHSA-fph2-r4qg-9576 | valid_release_specific_reference | `3b90c8cc82fa` | `d6a8da38fb33` |
| T1-d18f404a79e6d2901661 | parse-server 9.6.0-alpha.42 | patched | GHSA-fph2-r4qg-9576 | valid_release_specific_reference | `fb15851d7f0a` | `59130e349730` |
