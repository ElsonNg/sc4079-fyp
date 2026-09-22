# Exact-fix context for validation v6 and v7

`sources.json` records the URL, repository, complete revision, file, local path and raw SHA-256 of 19 public source/license snapshots. The run locks pin the metadata and snapshots. All execution is local during reproduction; no packages are installed or downloaded by the suites.

The v6 suite uses `getEssenceMediaType` from Fastify's matching `lib/validation.js` at `436da4c0` to check body-validator selection.

The v7 suite uses:

- Undici cookie validators, ASCII character predicates and date formatting at `10d93fc3`, `3bf91ddb` and `af748404`. The `stringify` checks hold those same-fix helpers fixed across both source sides, isolating validation of unparsed cookie attributes. Domain validators are tested separately.
- Axios `shouldBypassProxy` and its complete local helper declarations at `fb3befb6` and `afca61a0`. The corresponding HTTP adapter snapshots establish the reference function's exact-fix provenance. Environment proxy lookup is explicitly stubbed; the bypass helper itself is real.

Unused Undici fetch-utility snapshots and the Fastify content-type-parser snapshot were collected during investigation and remain in the provenance inventory. Their presence does not confer validation on any cases; each accepted case identifies the helpers actually used.

MIT license files accompany the upstream snapshots. The suites require matching repository/revision/file identity, verify hashes, and check that the reference patched function appears in its source snapshot. Recorded evidence includes the exact extracted declarations and their hashes. These tests provide bounded automated evidence, not human review or full-package exploit testing.
