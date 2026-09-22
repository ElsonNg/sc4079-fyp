"""Check the labeled functions in both saved paired-demo scans."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parent


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _has_boundary_state(finding: dict, case: dict, status: str) -> bool:
    for state in finding["result"].get("vulnerability_states", []):
        if state.get("status") != status or state.get("fix_commit_sha") != case["fix_commit_sha"]:
            continue
        if any(alias.get("ghsa_id") == case["ghsa_id"] for alias in state.get("advisories", [])):
            return True
    return False


def _ai_locations(lines: list[str]) -> Counter:
    directory = ""
    locations = Counter()
    for line in lines:
        if line.endswith("/") and not line.startswith("  "):
            directory = "" if line == "./" else line
        elif line.startswith("  "):
            match = re.match(r"^  (.+?):(\d+)-\d+ (?:VULN|REVIEW)\b", line)
            if not match:
                raise ValueError(f"Invalid AI finding line: {line}")
            locations[(directory + match.group(1), int(match.group(2)))] += 1
    return locations


def main() -> int:
    manifest = _read_json(ROOT / "manifest.json")
    cases = manifest["cases"]
    helpers = manifest["helpers"]
    failures = []
    rows = []
    review_counts = {}

    for side, expected_priority, expected_state in (
        ("vulnerable", "automatic_vulnerability", "vulnerable"),
        ("patched", "informational_lineage", "patched"),
    ):
        artifact_dir = ROOT / side / ".provtrail"
        try:
            report = _read_json(artifact_dir / "latest-scan.json")
            sarif = _read_json(artifact_dir / "latest-scan.sarif")
            ai_lines = (artifact_dir / "latest-scan.ai.txt").read_text(encoding="utf-8").splitlines()
        except (OSError, ValueError) as exc:
            failures.append(f"{side}: read failed: {exc}")
            continue

        findings = report.get("findings", [])
        expected_count = len(cases) + len(helpers)
        if len(findings) != expected_count:
            failures.append(f"{side}: expected {expected_count} functions, found {len(findings)}")

        for case in cases:
            expected_name = case[f"{side}_function_name"]
            matches = [
                finding for finding in findings
                if finding.get("path") == case["file"] and finding.get("name") == expected_name
            ]
            if len(matches) != 1:
                failures.append(f"{side}/{case['file']}:{expected_name}: found {len(matches)} functions")
                continue
            finding = matches[0]
            if finding["result"].get("priority") != expected_priority:
                failures.append(f"{side}/{case['file']}:{expected_name}: expected {expected_priority}")
            if not _has_boundary_state(finding, case, expected_state):
                failures.append(f"{side}/{case['file']}:{expected_name}: expected {expected_state} state for {case['ghsa_id']}")
            rows.append(f"{side}/{case['file']}:{expected_name}: {finding['result']['priority']}, {expected_state} boundary")

        neutral_reviews = 0
        for helper in helpers:
            if helper.get("expected_status") != "neutral":
                failures.append(f"{helper['file']}:{helper['function_name']}: missing neutral label")
            matches = [
                finding for finding in findings
                if finding.get("path") == helper["file"]
                and finding.get("name") == helper["function_name"]
            ]
            if len(matches) != 1:
                failures.append(f"{side}/{helper['file']}:{helper['function_name']}: found {len(matches)} functions")
                continue
            priority = matches[0]["result"]["priority"]
            if priority == "automatic_vulnerability":
                failures.append(f"{side}/{helper['file']}:{helper['function_name']}: neutral function flagged vulnerable")
            neutral_reviews += priority == "manual_review"
            rows.append(f"{side}/{helper['file']}:{helper['function_name']}: neutral, {priority}")
        review_counts[side] = neutral_reviews

        sarif_results = sarif.get("runs", [{}])[0].get("results", [])
        actionable = [
            finding for finding in findings
            if finding["result"]["priority"] in {"automatic_vulnerability", "manual_review"}
        ]
        expected_locations = Counter(
            (finding["path"], finding["start_line"] + 1) for finding in actionable
        )
        sarif_locations = Counter(
            (
                unquote(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]),
                result["locations"][0]["physicalLocation"]["region"]["startLine"],
            )
            for result in sarif_results
        )
        if sarif_locations != expected_locations:
            failures.append(f"{side}: SARIF locations do not match actionable functions")
        expected_ai_summary = f"total={len(actionable)} vuln={len(cases) if side == 'vulnerable' else 0} review={neutral_reviews}"
        if not ai_lines or ai_lines[-1] != expected_ai_summary:
            failures.append(f"{side}: AI summary does not match {expected_ai_summary}")
        try:
            if _ai_locations(ai_lines) != expected_locations:
                failures.append(f"{side}: AI locations do not match actionable functions")
        except ValueError as exc:
            failures.append(f"{side}: {exc}")

    if failures:
        for failure in failures:
            print(f"FAIL {failure}")
        return 1
    for row in rows:
        print(row)
    print(
        f"PASS {len(cases)} vulnerable targets and {len(cases)} patched targets, "
        "with matching exports"
    )
    print(
        "OBSERVED neutral manual reviews: "
        f"vulnerable={review_counts['vulnerable']}, patched={review_counts['patched']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
