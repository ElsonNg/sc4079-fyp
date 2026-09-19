# jscpd clone-detection pilot

Date: 2026-09-19. Tool: jscpd 5.3.0. This is a **clone-detection-only** pilot,
not vulnerability classification: a sample is detected when jscpd reports a
cross-file clone between a known source function and its candidate. Advisory,
CWE, and patched/vulnerable status are not part of the score.

## Samples and settings

The 30 samples come from 30 distinct origins:

| Label | Count | Construction |
|---|---:|---|
| Type 1 | 8 | Exact copy of a corpus function |
| Type 2 | 8 | Pure deterministic AST identifier rename of a corpus function |
| Type 3 | 7 | Existing LLM-transformed Type-3 positive candidates |
| Type 4 | 7 | Existing LLM-transformed Type-4 positive candidates |

Type-1 and Type-2 samples are JavaScript. Type-3 and Type-4 each contain four
JavaScript and three TypeScript samples. Each source/candidate pair was scanned
in an isolated two-file directory. All runs used `--mode weak` to exclude
comment tokens. No negative/non-clone pairs were included; this pilot measures
retrieval sensitivity, not precision or false-positive rate.

Three pinned configurations were tried:

- Default: `--min-lines 5 --min-tokens 50`.
- Renamed: default plus `--ignore-identifiers`.
- Near-miss: `--min-lines 3 --min-tokens 20 --ignore-identifiers
  --max-gap-lines 2 --similarity 0.7`.

## Results

The first number counts any cross-file clone. The number in parentheses counts
samples for which at least one reported clone spans at least half of the
candidate's lines. The latter is a stricter proxy for target-function retrieval,
though line spans are not equivalent to semantic coverage.

| Setting | Type 1 | Type 2 | Type 3 | Type 4 | Any match total |
|---|---:|---:|---:|---:|---:|
| Default | 6/8 (6/8) | 1/8 (0/8) | 0/7 (0/7) | 2/7 (0/7) | 9/30 |
| Renamed | 6/8 (6/8) | 6/8 (5/8) | 6/7 (5/7) | 2/7 (0/7) | 20/30 |
| Near-miss | 8/8 (8/8) | 6/8 (6/8) | 7/7 (7/7) | 4/7 (4/7) | 25/30 |

Two exact Type-1 functions have fewer code tokens than the 50-token default
threshold; both are recovered by the 20-token near-miss setting. The two missed
Type-2 functions are short functions whose only change is an identifier rename.

## Interpretation and limits

jscpd is effective at Type-1/Type-2 retrieval once thresholds and renaming are
enabled. Its structural setting also retrieves all seven selected Type-3
rewrites. Four of seven Type-4-labelled rewrites are retrieved under the
near-miss setting; three are not.

The Type-4 labels describe **generation intent**, not a guarantee of pure
semantic-only cloning. Two Type-4-labelled samples contain large exact copied
regions and are already found by default jscpd. Therefore 4/7 must not be
presented as pure Type-4 semantic-clone recall. A stricter Type-4 benchmark
requires manual review or a predeclared similarity filter, followed by a fresh
test set. The 30-sample pilot also has no non-clone controls and is too small to
establish comparative accuracy.

The selection and runner are in
[`scripts/run_jscpd_clone_30.py`](../scripts/run_jscpd_clone_30.py). Per-case
results and raw jscpd JSON are under `eval/comparison_raw/jscpd_clone_30/`.

## Matched-pool contrast with ProvTrail retrieval

For a direct retrieval comparison, both tools were given the same 30 labelled
origins, including each origin's vulnerable and patched function snapshots.
The task was to connect each candidate to its **correct source origin**, not to
decide whether that candidate was vulnerable. jscpd was credited for any
cross-file clone to either snapshot of the correct origin. ProvTrail was
credited when a correct-origin hash hit or region aggregate reached its normal
top-five retrieval shortlist; verification decisions were excluded.

| Tool/configuration | Type 1 | Type 2 | Type 3 | Type 4 | Total |
|---|---:|---:|---:|---:|---:|
| jscpd default | 6/8 | 1/8 | 0/7 | 2/7 | 9/30 |
| jscpd renamed | 6/8 | 5/8 | 6/7 | 2/7 | 19/30 |
| jscpd near-miss | 8/8 | 6/8 | 7/7 | 4/7 | 25/30 |
| ProvTrail hash + region retrieval | 8/8 | 8/8 | 7/7 | 7/7 | 30/30 |

ProvTrail's correct origin was a hash/abstracted-hash hit in 16 cases and a
region-retrieval hit in 14; every region hit ranked first among aggregates.
jscpd's near-miss setting also linked two candidates to one unrelated origin
in addition to their correct origins. Neither observation is a measured
false-positive rate, because the 30 tasks contain no non-clone targets.

This matched pool avoids corpus-version drift in nine older deterministic
fixtures. It is deliberately much smaller than ProvTrail's production corpus,
so 30/30 is an **in-pool pilot**, not a full-corpus recall estimate. jscpd's
Type-4 score remains affected by the generator-intent labels described above.
The scoring excludes ProvTrail's vulnerability verdict, but its region index is
still built from vulnerable/patched fix boundaries; this comparison isolates the
*output being measured* (source linkage), not every piece of upstream knowledge
available to the two methods.
The contrast runner is
[`scripts/compare_clone_30.py`](../scripts/compare_clone_30.py), and its
per-case results are in `eval/comparison_raw/jscpd_clone_30/contrast.json`.

## Local speed check

On one Windows run of the matched pool, jscpd scanned the 90 input files in
0.16 seconds (default), 0.12 seconds (renamed), and 0.12 seconds (near-miss).
ProvTrail took 11.63 seconds to build the 30-origin/120-region-pair index and
13.56 seconds to encode/query 905 candidate regions for the 30 candidates.
The model weights were available in the local cache. These are single-run
wall-clock measurements, not a controlled throughput benchmark; ProvTrail's
candidate phase includes model loading, and a persistent prebuilt index would
remove its one-time indexing cost. The qualitative result is clear: jscpd is
substantially faster for this small pool, while ProvTrail retrieved more of
the labelled source origins.

## 100-positive clone-detection extension

The 30 pilot cases were retained, then 70 more were selected from the existing
expanded positive fixtures **without using scanner outcomes**. The resulting
set has 100 distinct source origins: 25 per clone-intent label, with 12
JavaScript and 13 TypeScript cases in each label. New Type-1 cases are exact
copies; new Type-2 cases apply one declared-identifier rename; Type-3/Type-4
cases use the existing generated candidate text. The Type-4 label still denotes
generation intent, not manually verified semantic-only cloning.

Both tools saw one pool containing both vulnerable and patched snapshots for
each of the 100 origins, plus the 100 candidates (300 files total). The
primary score is binary: did a
candidate connect to **any** reference function? It does not use advisory,
vulnerability, or CVE verdicts. The same pinned jscpd 5.3.0 settings from the
pilot were used; no threshold was retuned on the new 70 cases.
After reviewing the short-case misses, we also ran an **exploratory**
one-line sensitivity setting (`--min-lines 1`, still `--min-tokens 20`);
it must not be presented as a prespecified confirmatory configuration.

| Tool / setting | Type 1 | Type 2 | Type 3 | Type-4 intent | Total |
|---|---:|---:|---:|---:|---:|
| jscpd default | 14/25 | 13/25 | 4/25 | 9/25 | 40/100 |
| jscpd renamed | 14/25 | 18/25 | 16/25 | 9/25 | 57/100 |
| jscpd near-miss, pooled scan | 23/25 | 22/25 | 22/25 | 18/25 | 85/100 |
| jscpd near-miss, source-pair scan | 24/25 | 23/25 | 23/25 | 19/25 | 89/100 |
| jscpd 1-line/20-token, pooled scan | 23/25 | 22/25 | 22/25 | 19/25 | 86/100 |
| jscpd 1-line/20-token, source-pair scan | 24/25 | 23/25 | 23/25 | 19/25 | 89/100 |
| ProvTrail hash + region retrieval | 25/25 | 25/25 | 25/25 | 25/25 | 100/100 |

The pooled jscpd scan reports duplicates selectively when several files share
code: three Type-1–3 cases that appear missed in the pool are detected when
their source origin is scanned separately. The source-pair scan includes each
origin's vulnerable and patched snapshots plus its candidate. It gives jscpd
the easier task of knowing which source pair to compare, so **89/100** is the
more generous clone-sensitivity figure, while **85/100** describes whole-pool
behavior. For a stricter origin-link check, all 85 pooled jscpd positives
connected the correct origin. ProvTrail connected the
correct origin in 99/100; one Type-4-intent case had its true source at raw
rank 7, outside the standard top-five shortlist, while other sources did
reach that shortlist. This is why the binary 100/100 must not be described as
perfect source attribution. jscpd also linked some candidates to additional
unrelated origins; without non-clone controls, those links do not establish a
false-positive rate.

The one-line setting finds one additional Type-4-intent case in the pooled
scan but does not improve the source-pair score. In particular, jscpd still
does not report the one-line Electron exact copy. A separate probe with both
`--min-lines 1` and `--min-tokens 1` also produced no duplicate for that
pair; its miss cannot be attributed to the configured line minimum alone.

This is a **positive-only sensitivity comparison**, not an accuracy or
precision study. The cases are not independent random draws: they come from
16 repositories, with several cases from the same repository. Type-4 labels
need a separate semantic-clone audit, and non-clone controls are still needed
to measure false alarms. ProvTrail's index uses vulnerable/patched fix
boundaries, even though this score excludes its vulnerability verdict.

The fixed selection and runner are in
[`scripts/compare_clone_100.py`](../scripts/compare_clone_100.py). The case
manifest and per-case outputs are under
`eval/comparison_raw/jscpd_clone_100/` (ignored evaluation artifacts).
On this single local run, jscpd's near-miss pool scan took 0.164 seconds;
ProvTrail took 15.652 seconds to build its index and 39.940 seconds to
encode/query 4,083 candidate regions. These are not controlled speed
benchmarks, and ProvTrail's timing includes model initialization.
