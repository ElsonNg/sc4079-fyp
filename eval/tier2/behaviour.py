"""Bounded JavaScript litmus tests for extracted security boundaries.

The same harness runs vulnerable, patched and candidate source in fresh VMs.
Admission requires the originals to differ and the candidate to match its side.
These tests establish the exercised security behaviour, not universal equivalence.
"""
from __future__ import annotations
import json
from pathlib import Path
import subprocess
from eval.ablation.common import digest

HARNESSES = {
    ("qs", "parseObject"): "qs-prototype-assignment",
    ("qs", "parseObjectRecursive"): "qs-prototype-assignment",
    ("lodash", "safeGet"): "lodash-prototype-read",
    ("minimist", "isConstructorOrProto"): "minimist-prototype-predicate",
    ("semver", "parse"): "semver-length-and-exception-guards",
    ("moment", "preprocessRFC2822"): "moment-nested-comment-regex",
}


def check(record, entry):
    name = HARNESSES.get((entry.advisory.package_name, entry.origin.function_name))
    if not name or entry.origin.source_language != "javascript":
        return None
    script = Path(__file__).with_name("behaviour.cjs")
    payload = {"harness": name, "sources": [entry.vulnerable_function, entry.patched_function, record["candidate_source"]]}
    try:
        result = subprocess.run(["node", "--max-old-space-size=128", str(script)], input=json.dumps(payload),
                                text=True, capture_output=True, timeout=10, check=True)
        evidence = json.loads(result.stdout)
        expected = evidence["vulnerable"] if record["expected_status"] == "flagged" else evidence["patched"]
        accepted = evidence["vulnerable"] != evidence["patched"] and evidence["candidate"] == expected
        return {"harness": name, "harness_sha256": digest(script.read_bytes()), "reviewer_type": "automated",
                "method": "executable_security_litmus", "accepted": accepted, "observations": evidence,
                "source_hashes": [digest(s) for s in payload["sources"]],
                "scope": "Distinguishing boundary litmus plus ordinary controls; fresh VM per source. Dependency stubs are explicit in the harness. Not proof of all runtime behaviour."}
    except (subprocess.SubprocessError, OSError, ValueError) as exc:
        return {"harness": name, "accepted": False, "error": str(exc), "method": "executable_security_litmus"}
