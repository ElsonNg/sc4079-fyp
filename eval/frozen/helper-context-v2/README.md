# Exact-fix helper context for validation v5

`sources.json` records URLs, repository revisions, local paths and raw SHA-256 hashes for four public source files and their MIT licenses. These are supporting test inputs, not additional corpus cases.

- Electron `parse-features-string.ts` at fixes `30cf3882`, `4eff3dc0`, and `fe2e7d00`: the actual numeric coercion rules, feature parser, allowed web preferences, and allowed window options. Only named declarations are extracted; imports and type-only declarations are not executed. Node strips TypeScript annotations.
- Minimist `index.js` at fix `c2b98197`: the exact `isConstructorOrProto` helper. The CLI parser is not executed; the reference/candidate `setKey` is tested directly with fresh VM-local objects.

The suite requires the cached source hash, repository, fix revision, file path and reference patched function to agree before using a helper. The v5 run lock pins all eight snapshots and metadata. Reproduction uses local files and makes no downloads.

The other tests exercise isolated permission, MIME, request scheduling, address normalization and error-handling boundaries. Their service stubs and limits are recorded per case. These results are automated evidence for the stated boundaries, not full-package exploit tests or human review.
