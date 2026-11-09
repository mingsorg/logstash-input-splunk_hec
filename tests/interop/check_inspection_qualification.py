#!/usr/bin/env python3
"""Require current-artifact inspection, ingestion guarantees and independent review."""
import json
import sys
import runtime
import review_journal
import review_inspection
import check_assembly_qualification
from inspection_qualification import BASELINE_SHA256

def main():
    artifact=runtime.artifact_info();validators=runtime.validators_info()
    inspection=json.loads((runtime.EVIDENCE/'inspection.json').read_text())
    required={'published-v3','original-v2','persisted-blocked','short-header','short-authenticated-payload','checksum','bad-complete-header',
              'authenticated-bad-operation','ambiguous-publication','missing-lock','symlink-entry','special-file','entry-budget','java-exclusive-lock','java-shared-lock',
              'compacted-v3','compacted-torn','public-directory'}
    valid=inspection.get('status')=='pass' and inspection.get('artifact')==artifact and inspection.get('validators')==validators and inspection.get('baseline',{}).get('sha256')==BASELINE_SHA256
    rows=inspection.get('runs',[])
    valid=valid and {row.get('role') for row in rows}=={'minimum','latest'} and len(rows)==2
    for row in rows:
        valid=valid and row.get('status')=='pass' and row.get('image')==runtime.P['logstash.'+row['role']+'.image'] and row.get('production_copy_matches') and row.get('independent_oracle_matches')
        valid=valid and row.get('network')=='none' and all(row.get(key) is True for key in ('no_checkout','no_python','no_compiler_at_runtime','read_only_root',
            'unprivileged_owner','read_only_spool_mount','unreadable_owner_file_refused','schema_outputs_validated','compacted_and_torn_recovery_match'))
        valid=valid and {case.get('case') for case in row.get('cases',[])}>=required and all(case.get('inventory_unchanged') is True for case in row.get('cases',[]))
    review_journal.CLAIMS=review_inspection.CLAIMS
    # This fresh gate checks the gem against rebuilt classes/docs and reruns the original Java/Python regressions.
    original=check_assembly_qualification.main()
    summary=json.loads((runtime.EVIDENCE/'qualification-summary.json').read_text())
    summary['checks']['installed_inspection']=bool(valid)
    summary['status']='pass' if original==0 and valid else 'fail'
    summary['release_ready']=summary['status']=='pass' and summary['independent_review']['status']=='complete'
    (runtime.EVIDENCE/'qualification-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({key:summary[key] for key in ('artifact','status','checks','independent_review','release_ready')},indent=2))
    return 0 if summary['release_ready'] else 1

if __name__=='__main__':sys.exit(main())
