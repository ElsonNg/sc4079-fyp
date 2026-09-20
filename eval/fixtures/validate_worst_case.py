"""End-to-end pilot: hand-authored Type-2/3 (renamed + restructured) clones through
the FULL three-stage pipeline (hash -> retrieval -> verification), evaluated stage by
stage -- not just a final verdict.

WHY THIS EXISTS: every prior validation in this project (self-anchor/self-clear,
validate_e2e.py) tests a candidate that is byte-identical to something already stored
in the corpus. That is the floor, not the target -- the tool exists to catch a
patched-but-reintroduced OR renamed/reworded vulnerability, which is never an exact
text match to anything in the corpus. This script is the first attempt to measure
that actual case.

METHODOLOGY, DISCLOSED (read before trusting a headline number from this script):

- Clones in CLONE_PAIRS are HAND-AUTHORED by the same person who built Stage 7, not
  produced by an automated refactoring tool (none exists in this pipeline). That is a
  real source of bias -- these clones may unconsciously avoid exactly the kind of
  transformation that would break the tool. Treat this as a pilot that characterizes
  a failure mode, not a statistically powered benchmark.
- N=13 unique vulnerability patterns (19 corpus entries once you count 6 advisories
  that turned out to share byte-identical underlying code -- see BUILDPATH_ADVISORIES
  below), selected one-per-advisory from the 21 real advisories (GHSA-43fc-jf86-j433,
  the prettier-reformat commit, is excluded entirely -- there is no vulnerability to
  preserve when "cloning" a cosmetic diff). Two entries (dispatchHttpRequest,
  dispatchXhrRequest, both >6800 chars) are excluded from hand-cloning as impractical
  to transcribe reliably by hand without transcription-error risk confounding the
  result -- selection is auditable via SELECTED_GHSA_IDS below.
- Each clone applies BOTH identifier renaming (Type-2) AND at least one structural
  change -- a flattened/split conditional, a converted loop form, reordered
  independent statements (Type-3) -- not renaming alone, since renaming-only clones
  are already known to pass (see RENAMED_AUTHORIZE_CLONE in tests/test_verification.py).

WHAT GETS MEASURED PER STAGE (not just pass/fail):
- Stage 1 (hash): does the clone produce a false-positive hash match (exact or
  abstracted)? A match here would be concerning -- it means the fast path claims
  certainty about a candidate that is not actually a byte/structure match.
- Stage 2 (retrieval): the RANK and SIMILARITY SCORE of the correct entry among ALL
  corpus entries (not just the selected ones -- a real search, not an in-set lookup),
  plus whether retrieval's own default threshold (0.7) would have silently dropped it
  before rank ever mattered.
- Stage 7, two ways: (a) ISOLATED -- hand the correct entry directly to
  verify_candidate, same as validate_e2e.py, to measure verification's own accuracy
  independent of retrieval; (b) END-TO-END -- run verify() against whatever retrieval
  actually returned, the real compounded number a live scan would produce. The gap
  between (a) and (b) is retrieval's contribution to failure, isolated from
  verification's.
- Stage 7's three-way bucket (flagged / cleared / manual_review), not a collapsed
  pass/fail -- a clone landing in manual_review is a materially different outcome
  from landing in the wrong bucket entirely.

Run in VALIDATION mode first (confirms the harness reproduces exact-text results
before trusting it on clones), then in CLONE mode:
    PYTHONPATH=. .venv/bin/python scripts/validate_worst_case.py --mode=validate
    PYTHONPATH=. .venv/bin/python scripts/validate_worst_case.py --mode=clone
"""
import argparse
import sys

from corpus.controller.store import load_entries
from pipeline.controller.embedding import DEFAULT_MODEL_ID
from pipeline.controller.hashing import build_hash_index, lookup
from pipeline.controller.hierarchy import EmbeddingCache
from pipeline.controller.retrieval import build_faiss_index, query
from pipeline.controller.verification import index_corpus_entries, verify, verify_candidate

# --- Selection: one entry per advisory, excluding the reformat commit and the two
# largest (hand-transcription-impractical) entries. Auditable list. ------------------

EXCLUDED_GHSA_IDS = {
    "GHSA-43fc-jf86-j433",  # prettier reformat commit -- no vulnerability to clone
    "GHSA-4w2v-q235-vp99",  # dispatchHttpRequest, 8967 chars -- too large to hand-clone reliably
    "GHSA-wf5p-g6vw-rhxx",  # dispatchXhrRequest, 6859 chars -- same reason
}

# 6 advisories whose selected entry turned out to be byte-identical underlying code
# (axios's formDataToJSON prototype-pollution depth guard, fixed the same way and
# re-published across multiple advisories/releases). One clone pair is authored and
# reused across all 6 -- retrieval is expected to be unable to disambiguate WHICH of
# the 6 is "correct" from embedding similarity alone, since their vulnerable_function
# text is identical. That is a genuine corpus characteristic, not a clone-writing gap.
BUILDPATH_ADVISORIES = {
    "GHSA-42h9-826w-cgv3", "GHSA-7q8q-rj6j-mhjq", "GHSA-f4gw-2p7v-4548",
    "GHSA-gcfj-64vw-6mp9", "GHSA-hcpx-6fm6-wx23", "GHSA-mmx7-hfxf-jppx",
}

SELECTED_GHSA_IDS = BUILDPATH_ADVISORIES | {
    "GHSA-3p68-rc4w-qgx5", "GHSA-4hjh-wcwx-xvwj", "GHSA-62hf-57xw-28j9",
    "GHSA-8hc4-vh64-cxmj", "GHSA-cph5-m8f7-6c5x", "GHSA-fvcv-3m26-pcqx",
    "GHSA-j5f8-grm9-p9fc", "GHSA-jr5f-v2jv-69x6", "GHSA-q8qp-cvcw-x6jj",
    "GHSA-qj83-cq47-w5f8", "GHSA-qw6h-vgh9-j6wx", "GHSA-rv95-896h-c2vc",
}

_BUILDPATH_VULNERABLE = """
function applyPath(key, val) {
  writePath(splitPropPath(key), val, target, 0);
}
"""
_BUILDPATH_PATCHED = """
function applyPath(key, val) {
  var segments = splitPropPath(key);
  checkPathDepth(segments);
  writePath(segments, val, target, 0);
}
"""

# ghsa_id -> (vulnerable_clone, patched_clone). Hand-authored: renamed identifiers +
# at least one structural change (flattened/split conditional, loop-form conversion,
# reordered independent statements), not renaming alone.
CLONE_PAIRS: dict[str, tuple[str, str]] = {
    "GHSA-3p68-rc4w-qgx5": (
        """
function configureProxy(reqOptions, proxyConfig, target) {
  var activeProxy = proxyConfig;
  if (!activeProxy && activeProxy !== false) {
    var detectedProxyUrl = getProxyForUrl(target);
    if (detectedProxyUrl) {
      activeProxy = url.parse(detectedProxyUrl);
      activeProxy.host = activeProxy.hostname;
    }
  }
  if (activeProxy) {
    if (activeProxy.auth) {
      if (activeProxy.auth.username || activeProxy.auth.password) {
        activeProxy.auth = (activeProxy.auth.username || '') + ':' + (activeProxy.auth.password || '');
      }
      var encodedAuth = Buffer.from(activeProxy.auth, 'utf8').toString('base64');
      reqOptions.headers['Proxy-Authorization'] = 'Basic ' + encodedAuth;
    }
    reqOptions.headers.host = reqOptions.hostname + (reqOptions.port ? ':' + reqOptions.port : '');
    reqOptions.hostname = activeProxy.host;
    reqOptions.host = activeProxy.host;
    reqOptions.port = activeProxy.port;
    reqOptions.path = target;
    if (activeProxy.protocol) {
      reqOptions.protocol = activeProxy.protocol;
    }
  }
  reqOptions.beforeRedirects.proxy = function onRedirect(redirectOpts) {
    configureProxy(redirectOpts, proxyConfig, redirectOpts.href);
  };
}
""",
        """
function configureProxy(reqOptions, proxyConfig, target) {
  var activeProxy = proxyConfig;
  if (!activeProxy && activeProxy !== false) {
    var detectedProxyUrl = getProxyForUrl(target);
    if (detectedProxyUrl && !shouldBypassProxy(target)) {
      activeProxy = url.parse(detectedProxyUrl);
      activeProxy.host = activeProxy.hostname;
    }
  }
  if (activeProxy) {
    if (activeProxy.auth) {
      if (activeProxy.auth.username || activeProxy.auth.password) {
        activeProxy.auth = (activeProxy.auth.username || '') + ':' + (activeProxy.auth.password || '');
      }
      var encodedAuth = Buffer.from(activeProxy.auth, 'utf8').toString('base64');
      reqOptions.headers['Proxy-Authorization'] = 'Basic ' + encodedAuth;
    }
    reqOptions.headers.host = reqOptions.hostname + (reqOptions.port ? ':' + reqOptions.port : '');
    reqOptions.hostname = activeProxy.host;
    reqOptions.host = activeProxy.host;
    reqOptions.port = activeProxy.port;
    reqOptions.path = target;
    if (activeProxy.protocol) {
      reqOptions.protocol = activeProxy.protocol;
    }
  }
  reqOptions.beforeRedirects.proxy = function onRedirect(redirectOpts) {
    configureProxy(redirectOpts, proxyConfig, redirectOpts.href);
  };
}
""",
    ),
    "GHSA-4hjh-wcwx-xvwj": (
        """
function onStreamAborted() {
  if (isRejected) {
    return;
  }
  dataStream.destroy();
  rejectPromise(new AxiosError(
    'maxContentLength size of ' + reqConfig.maxContentLength + ' exceeded',
    AxiosError.ERR_BAD_RESPONSE,
    reqConfig,
    priorRequest
  ));
}
""",
        """
function onStreamAborted() {
  if (isRejected) {
    return;
  }
  responseDataStream.destroy();
  rejectPromise(new AxiosError(
    'maxContentLength size of ' + reqConfig.maxContentLength + ' exceeded',
    AxiosError.ERR_BAD_RESPONSE,
    reqConfig,
    priorRequest
  ));
}
""",
    ),
    "GHSA-62hf-57xw-28j9": (
        """
function visitEntry(item, itemKey) {
  var shouldRecurse =
    !(utils.isUndefined(item) || item === null) &&
    handler.call(formPayload, item, utils.isString(itemKey) ? itemKey.trim() : itemKey, currentPath, helpers);
  if (shouldRecurse === true) {
    walk(item, currentPath ? currentPath.concat(itemKey) : [itemKey]);
  }
}
""",
        """
function visitEntry(item, itemKey) {
  var shouldRecurse =
    !(utils.isUndefined(item) || item === null) &&
    handler.call(formPayload, item, utils.isString(itemKey) ? itemKey.trim() : itemKey, currentPath, helpers);
  if (shouldRecurse === true) {
    walk(item, currentPath ? currentPath.concat(itemKey) : [itemKey], currentDepth + 1);
  }
}
""",
    ),
    "GHSA-8hc4-vh64-cxmj": (
        """
function isFullyQualifiedURL(target) {
  // A URL is considered absolute if it begins with "<scheme>://".
  return /^([a-z][a-z\\d+\\-.]*:)\\/\\//i.test(target);
}
""",
        """
function isFullyQualifiedURL(target) {
  // A URL is considered absolute if it begins with "<scheme>://" or "//" (protocol-relative URL).
  return /^([a-z][a-z\\d+\\-.]*:)?\\/\\//i.test(target);
}
""",
    ),
    "GHSA-cph5-m8f7-6c5x": (
        """
function stripWhitespace(text) {
  return text.replace(/^\\s*/, '').replace(/\\s*$/, '');
}
""",
        """
function stripWhitespace(text) {
  return text.trim ? text.trim() : text.replace(/^\\s+|\\s+$/g, '');
}
""",
    ),
    "GHSA-fvcv-3m26-pcqx": (
        """
function sanitizeValue(val) {
  if (val === false || val == null) {
    return val;
  }
  return utils.isArray(val)
    ? val.map(sanitizeValue)
    : String(val).replace(/[\\r\\n]+$/, '');
}
""",
        """
function sanitizeValue(val) {
  if (val === false || val == null) {
    return val;
  }
  return utils.isArray(val) ? val.map(sanitizeValue) : removeTrailingCRLF(String(val));
}
""",
    ),
    "GHSA-j5f8-grm9-p9fc": (
        """
function onRedirect(redirectOpts) {
  configureProxy(redirectOpts, proxyConfig, redirectOpts.href);
}
""",
        """
function onRedirect(redirectOpts) {
  configureProxy(redirectOpts, proxyConfig, redirectOpts.href, true);
}
""",
    ),
    "GHSA-jr5f-v2jv-69x6": (
        """
function resolveFullPath(base, requested) {
  if (base && !isFullyQualifiedURL(requested)) {
    return joinURLs(base, requested);
  }
  return requested;
}
""",
        """
function resolveFullPath(base, requested, allowAbsolute) {
  var isRelative = !isFullyQualifiedURL(requested);
  if (base && (isRelative || allowAbsolute === false)) {
    return joinURLs(base, requested);
  }
  return requested;
}
""",
    ),
    "GHSA-q8qp-cvcw-x6jj": (
        """
function validateOptions(opts, rules, permitUnknown) {
  if (typeof opts !== 'object') {
    throw new AxiosError('options must be an object', AxiosError.ERR_BAD_OPTION_VALUE);
  }
  var names = Object.keys(opts);
  var idx = names.length;
  while (idx-- > 0) {
    var key = names[idx];
    var checker = rules[key];
    if (checker) {
      var val = opts[key];
      var outcome = val === undefined || checker(val, key, opts);
      if (outcome !== true) {
        throw new AxiosError('option ' + key + ' must be ' + outcome, AxiosError.ERR_BAD_OPTION_VALUE);
      }
      continue;
    }
    if (permitUnknown !== true) {
      throw new AxiosError('Unknown option ' + key, AxiosError.ERR_BAD_OPTION);
    }
  }
}
""",
        """
function validateOptions(opts, rules, permitUnknown) {
  if (typeof opts !== 'object') {
    throw new AxiosError('options must be an object', AxiosError.ERR_BAD_OPTION_VALUE);
  }
  var names = Object.keys(opts);
  var idx = names.length;
  while (idx-- > 0) {
    var key = names[idx];
    var hasRule = Object.prototype.hasOwnProperty.call(rules, key);
    var checker = hasRule ? rules[key] : undefined;
    if (checker) {
      var val = opts[key];
      var outcome = val === undefined || checker(val, key, opts);
      if (outcome !== true) {
        throw new AxiosError('option ' + key + ' must be ' + outcome, AxiosError.ERR_BAD_OPTION_VALUE);
      }
      continue;
    }
    if (permitUnknown !== true) {
      throw new AxiosError('Unknown option ' + key, AxiosError.ERR_BAD_OPTION);
    }
  }
}
""",
    ),
    "GHSA-qj83-cq47-w5f8": (
        """
fetchSession(host, opts) {
  opts = Object.assign({ sessionTimeout: 1000 }, opts);
  var hostSessions;
  if ((hostSessions = this.pool[host])) {
    var count = hostSessions.length;
    for (var idx = 0; idx < count; idx++) {
      var pair = hostSessions[idx];
      var handle = pair[0];
      var savedOpts = pair[1];
      if (!handle.destroyed && !handle.closed && util.isDeepStrictEqual(savedOpts, opts)) {
        return handle;
      }
    }
  }

  var sess = connect(host, opts);
  var wasRemoved;

  var dropSession = () => {
    if (wasRemoved) {
      return;
    }
    wasRemoved = true;
    var list = hostSessions, count = list.length, idx = count;
    while (idx--) {
      if (list[idx][0] === sess) {
        list.splice(idx, 1);
        if (count === 1) {
          delete this.pool[host];
          return;
        }
      }
    }
  };

  var origRequest = sess.request;
  var timeoutMs = opts.sessionTimeout;

  if (timeoutMs != null) {
    var timer;
    var openStreams = 0;
    sess.request = function () {
      var stream = origRequest.apply(this, arguments);
      openStreams++;
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      stream.once('close', () => {
        if (!--openStreams) {
          timer = setTimeout(() => {
            timer = null;
            dropSession();
          }, timeoutMs);
        }
      });
      return stream;
    };
  }

  sess.once('close', dropSession);
  var list = this.pool[host], record = [sess, opts];
  list ? this.pool[host].push(record) : hostSessions = this.pool[host] = [record];
  return sess;
}
""",
        """
fetchSession(host, opts) {
  opts = Object.assign({ sessionTimeout: 1000 }, opts);
  var hostSessions;
  if ((hostSessions = this.pool[host])) {
    var count = hostSessions.length;
    for (var idx = 0; idx < count; idx++) {
      var pair = hostSessions[idx];
      var handle = pair[0];
      var savedOpts = pair[1];
      if (!handle.destroyed && !handle.closed && util.isDeepStrictEqual(savedOpts, opts)) {
        return handle;
      }
    }
  }

  var sess = http2.connect(host, opts);
  var wasRemoved;

  var dropSession = () => {
    if (wasRemoved) {
      return;
    }
    wasRemoved = true;
    var list = hostSessions, count = list.length, idx = count;
    while (idx--) {
      if (list[idx][0] === sess) {
        list.splice(idx, 1);
        if (count === 1) {
          delete this.pool[host];
          return;
        }
      }
    }
  };

  var origRequest = sess.request;
  var timeoutMs = opts.sessionTimeout;

  if (timeoutMs != null) {
    var timer;
    var openStreams = 0;
    sess.request = function () {
      var stream = origRequest.apply(this, arguments);
      openStreams++;
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      stream.once('close', () => {
        if (!--openStreams) {
          timer = setTimeout(() => {
            timer = null;
            dropSession();
          }, timeoutMs);
        }
      });
      return stream;
    };
  }

  sess.once('close', dropSession);
  var list = this.pool[host], record = [sess, opts];
  list ? this.pool[host].push(record) : hostSessions = this.pool[host] = [record];
  return sess;
}
""",
    ),
    "GHSA-qw6h-vgh9-j6wx": (
        """
function renderRedirectBody() {
  var safeAddress = escapeHtml(destination);
  content = '<p>' + statusMessages[code] + '. Redirecting to <a href="' + safeAddress + '">' + safeAddress + '</a></p>';
}
""",
        """
function renderRedirectBody() {
  var safeAddress = escapeHtml(destination);
  content = '<p>' + statusMessages[code] + '. Redirecting to ' + safeAddress + '</p>';
}
""",
    ),
    "GHSA-rv95-896h-c2vc": (
        """
function setLocation(target) {
  var dest = target;
  if (target === 'back') {
    dest = this.req.get('Referrer') || '/';
  }
  return this.set('Location', encodeUrl(dest));
}
""",
        """
function setLocation(target) {
  var dest = target;
  if (target === 'back') {
    dest = this.req.get('Referrer') || '/';
  }
  var destLower = dest.toLowerCase();
  var encodedDest = encodeUrl(dest);
  if (destLower.indexOf('https://') === 0 || destLower.indexOf('http://') === 0) {
    try {
      var parsedDest = urlParse(dest);
      var parsedEncoded = urlParse(encodedDest);
      if (parsedDest.host !== parsedEncoded.host) {
        return this.set('Location', dest);
      }
    } catch (e) {
      return this.set('Location', dest);
    }
  }
  return this.set('Location', encodedDest);
}
""",
    ),
}
for _ghsa in BUILDPATH_ADVISORIES:
    CLONE_PAIRS[_ghsa] = (_BUILDPATH_VULNERABLE, _BUILDPATH_PATCHED)


def _select_entries():
    entries = load_entries()
    by_ghsa = {e.advisory.ghsa_id: e for e in entries if e.advisory.ghsa_id in SELECTED_GHSA_IDS}
    missing = SELECTED_GHSA_IDS - set(by_ghsa)
    if missing:
        raise RuntimeError(f"Selected advisories missing from corpus: {missing}")
    return entries, [by_ghsa[g] for g in sorted(SELECTED_GHSA_IDS)]


def _stage1(candidate_source, hash_index):
    matches = lookup(candidate_source, hash_index)
    if not matches:
        return "no_match"
    return "+".join(sorted({m.match_type for m in matches}))


def _stage2(candidate_source, retrieval_index, correct_key):
    matches = query(candidate_source, retrieval_index, k=10, threshold=0.0)
    for rank, m in enumerate(matches, start=1):
        key = (m.advisory.ghsa_id, m.origin.fix_commit_sha, m.origin.file_path, m.origin.function_name)
        if key == correct_key:
            below_default_threshold = m.similarity < 0.7
            return rank, m.similarity, below_default_threshold
    return None, None, None


def _run_one(label, candidate_source, entry, hash_index, retrieval_index, corpus_index, cache, expected_status):
    correct_key = (entry.advisory.ghsa_id, entry.origin.fix_commit_sha, entry.origin.file_path, entry.origin.function_name)

    hash_result = _stage1(candidate_source, hash_index)

    rank, similarity, below_threshold = _stage2(candidate_source, retrieval_index, correct_key)

    isolated = verify_candidate(candidate_source, entry, cache)

    matches_at_default_threshold = query(candidate_source, retrieval_index, k=10, threshold=0.7)
    e2e_result = None
    if matches_at_default_threshold:
        e2e_results = verify(candidate_source, matches_at_default_threshold, corpus_index)
        for m, r in zip(matches_at_default_threshold, e2e_results):
            key = (m.advisory.ghsa_id, m.origin.fix_commit_sha, m.origin.file_path, m.origin.function_name)
            if key == correct_key:
                e2e_result = r
                break

    rank_str = f"rank={rank} sim={similarity:.3f}{' <thresh' if below_threshold else ''}" if rank else "NOT IN TOP 10"
    e2e_str = e2e_result.status if e2e_result is not None else "NOT RETRIEVED (missed by default threshold)"
    correct_isolated = isolated.status == expected_status
    correct_e2e = e2e_result is not None and e2e_result.status == expected_status

    print(
        f"  [{label}] hash={hash_result:12s} retrieval=({rank_str})  "
        f"isolated={isolated.status:14s}({isolated.verification_score:+.3f}){'  OK' if correct_isolated else '  MISS'}  "
        f"e2e={e2e_str:14s}{'  OK' if correct_e2e else '  MISS' if e2e_result is not None else ''}"
    )
    return {
        "label": label, "hash_result": hash_result, "rank": rank, "similarity": similarity,
        "below_threshold": below_threshold, "isolated_status": isolated.status,
        "isolated_correct": correct_isolated, "e2e_status": e2e_result.status if e2e_result else None,
        "e2e_correct": correct_e2e,
    }


def main(mode: str) -> None:
    all_entries, selected = _select_entries()
    print(f"Full corpus: {len(all_entries)} entries")
    print(f"Selected advisories: {len(selected)} (mode={mode})")

    hash_index = build_hash_index(all_entries)
    retrieval_index = build_faiss_index(all_entries, model_id=DEFAULT_MODEL_ID)
    corpus_index = index_corpus_entries(all_entries)
    cache = EmbeddingCache()

    results = []
    for entry in selected:
        print(f"\n{entry.advisory.ghsa_id} / {entry.origin.function_name or '<anon>'}")
        if mode == "validate":
            vuln_candidate = entry.vulnerable_function
            patched_candidate = entry.patched_function
        else:
            vuln_candidate, patched_candidate = CLONE_PAIRS[entry.advisory.ghsa_id]

        results.append(_run_one("vuln-clone", vuln_candidate, entry, hash_index, retrieval_index, corpus_index, cache, "flagged"))
        results.append(_run_one("patch-clone", patched_candidate, entry, hash_index, retrieval_index, corpus_index, cache, "cleared"))

    n = len(results)
    iso_correct = sum(r["isolated_correct"] for r in results)
    e2e_correct = sum(r["e2e_correct"] for r in results)
    not_retrieved = sum(1 for r in results if r["e2e_status"] is None)
    hash_false_positive = sum(1 for r in results if r["hash_result"] != "no_match")
    print(f"\n{'='*70}")
    print(f"Mode: {mode}  |  N={n} candidate runs across {len(selected)} advisories")
    print(f"Stage 1 false-positive hash matches: {hash_false_positive}/{n}")
    print(f"Stage 7 isolated (retrieval bypassed) correct: {iso_correct}/{n} ({100*iso_correct/n:.1f}%)")
    print(f"Stage 7 end-to-end (through real retrieval) correct: {e2e_correct}/{n} ({100*e2e_correct/n:.1f}%)")
    print(f"  of which missed by retrieval entirely (never reached verification): {not_retrieved}/{n}")
    if mode == "clone":
        print(
            "\nReminder: clones are hand-authored by the tool's own developer -- N=13 unique "
            "patterns, a pilot characterizing a failure mode, not a statistically powered benchmark."
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["validate", "clone"], default="clone")
    args = parser.parse_args()
    main(args.mode)
