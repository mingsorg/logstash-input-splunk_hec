import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests/interop'))
import inspection_contract
import linux_inspection_tests
import review_inspection


class InspectionFixesTest(unittest.TestCase):
    def test_schema_checker_rejects_missing_wrong_and_unknown_values(self):
        schema={'type':'object','required':['format','count'],'additionalProperties':False,
            'properties':{'format':{'const':'v3'},'count':{'type':'integer','minimum':0}}}
        inspection_contract.validate(schema,{'format':'v3','count':1})
        for value in ({'format':'v3'},{'format':'v2','count':1},{'format':'v3','count':True},
                      {'format':'v3','count':-1},{'format':'v3','count':1,'secret':'x'}):
            with self.assertRaises(ValueError):inspection_contract.validate(schema,value)
        with self.assertRaises(ValueError):inspection_contract.validate({'const':1},True)
        with self.assertRaises(ValueError):inspection_contract.validate({'unsupported':True},{})

    def test_linux_result_must_have_current_run_capture(self):
        # Even a passing old XML with unchanged test names must not be reusable:
        # the output capture must belong to the new execution identity.
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
            root=Path(temporary);build=root/'build/linux-inspection'
            xml=build/'test-results/test'/('TEST-'+linux_inspection_tests.SUITE+'.xml')
            xml.parent.mkdir(parents=True)
            xml.write_text('<testsuite tests="11" failures="0" errors="0" skipped="0"><testcase name="same-name"/></testsuite>')
            capture=build/'inspection-captures/new-run/captured.json';capture.parent.mkdir(parents=True)
            capture.write_text(json.dumps({'run_id':'old-run'}))
            (root/'.cache/gradle-test/bin').mkdir(parents=True);(root/'.cache/gradle-test/bin/gradle').touch()
            evidence=root/'evidence';evidence.mkdir()
            with patch.multiple(linux_inspection_tests.runtime,ROOT=root,EVIDENCE=evidence,P={'gradle.version':'test','logstash.latest.image':'test'}), \
                 patch.object(linux_inspection_tests.runtime,'artifact_info',return_value={'sha256':'artifact'}), \
                 patch.object(linux_inspection_tests.runtime,'validators_info',return_value='validators'), \
                 patch.object(linux_inspection_tests.runtime,'docker',return_value='fresh invocation') as docker, \
                 patch.object(linux_inspection_tests,'source_digest',return_value='source'), \
                 patch.object(linux_inspection_tests.uuid,'uuid4',return_value=type('Run',(),{'hex':'new-run'})()), \
                 patch.dict('os.environ',{'GRADLE_USER_HOME':str(root)}):
                with self.assertRaises(AssertionError):linux_inspection_tests.run_suite()
                self.assertTrue(docker.called)
                self.assertEqual('fail',json.loads((evidence/'linux-inspection.json').read_text())['status'])

    def test_failed_external_review_returns_nonzero_and_retains_diagnostics(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
            evidence=Path(temporary)
            failed=subprocess.CompletedProcess(['review'],1,stdout='{"is_error":true}',stderr='authentication failed')
            with patch.object(review_inspection.runtime,'EVIDENCE',evidence), \
                 patch.object(review_inspection.review_journal,'CLAIMS',review_inspection.review_journal.CLAIMS), \
                 patch.object(review_inspection.runtime,'artifact_info',return_value={'sha256':'artifact'}), \
                 patch.object(review_inspection.runtime,'validators_info',return_value='validators'), \
                 patch.object(review_inspection.review_journal,'reviewed_source',return_value=('source','digest','claims')), \
                 patch.object(review_inspection.subprocess,'run',return_value=failed), \
                 patch.object(review_inspection.check_assembly_qualification,'review_complete',return_value=False):
                self.assertEqual(1,review_inspection.main())
                identity=json.loads((evidence/'review-identity.json').read_text())
                self.assertEqual(3,len(identity['reports']))
                self.assertTrue(all(row['exit_code']==1 for row in identity['reports']))
                self.assertTrue(all((ROOT/row['file']).is_file() for row in identity['reports']))
