"""Tier 1 advisory validity is separate from exploitability validation."""
from collections import Counter
import hashlib
import json

from eval.tier1 import advisory_validity_audit as audit


def test_all_release_labels_have_advisory_and_version_provenance():
    rows,_=audit.audit()
    assert len(rows)==600
    assert Counter(r['reference_side'] for r in rows)=={'vulnerable':300,'patched':300}
    assert all(all(v for k,v in r['checks'].items() if k!='source_digest') for r in rows)
    assert Counter(r['verdict'] for r in rows)=={
        'valid_advisory_reference':532,
        'valid_release_specific_reference':16,
        'excluded_security_label':50,
        'excluded_incompatible_release_pair':2,
    }


def test_new_advisory_admissions_have_numbered_line_evidence():
    rows,_=audit.audit()
    newly_valid=[r for r in rows if r['previous_validation_status']=='needs_review']
    assert len(newly_valid)==178
    assert all(r['verdict']=='valid_advisory_reference' and r['line_review'] for r in newly_valid)
    mismatches=[r for r in rows if not r['checks']['source_digest']]
    assert len(mismatches)==18
    assert all(r['target_source_sha256']!=r['current_reference_sha256'] for r in mismatches)
    release_valid=[r for r in mismatches if r['verdict']=='valid_release_specific_reference']
    assert len(release_valid)==16
    assert all(r['historical_release_source_sha256']==r['target_source_sha256'] for r in release_valid)
    assert len([r for r in release_valid if r['package']=='ws' and r['historical_release_url']])==4


def test_report_lock_matches_generated_evidence():
    out=audit.OUTPUT
    lock=json.loads((out/'lock.json').read_text(encoding='utf8'))
    assert all(hashlib.sha256((audit.ROOT/name if name.startswith('eval/') else out/name).read_bytes()).hexdigest()==value
               for name,value in lock.items())
