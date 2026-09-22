# Pinned helper context for validation v4

These public upstream source snapshots provide missing definitions for the extracted-function tests in `eval/tier2/context_checks.py`. They are test context, not new corpus candidates or changes to the searchable reference database.

`sources.json` records each source URL, repository, revision, local path and raw SHA-256. Corresponding MIT license files are preserved here. The v4 run lock pins every snapshot and the metadata. Validation checks matching repository/fix identity and the presence of the reference patched function before extracting helpers.

- Moment: `isLocaleNameSane` from fix `4211bfc8f15746be4019bba557e29a7ba83d54c5`.
- Undici: actual token and header validation regex declarations from fix `66165d604fd0aee70a93ed5c44ad4cc2df395f80`.
- Fastify: parser helpers and companion methods from fix `62dde76f1f7aca76e38625fe8d983761f26e6fc9`. Constructor/add/getParser originals remain taken from the reference database and are matched to that fix.
- `content-type` v1.0.4: a pinned test dependency satisfying the matching Fastify package's `^1.0.4` declaration. This is not evidence of the historically installed dependency version.

Snapshots are read locally; reproduction does not fetch or install them. Only extracted definitions and the standalone content-type parser execute in bounded Node VMs. Tests record stub assumptions, observations and reviewer type. They establish the stated boundaries, not full-package exploitability or universal semantic equivalence.
