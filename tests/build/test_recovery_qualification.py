import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests/interop'))
import check_recovery_qualification as gate
from inspection_contract import validate


def origin(prefix=False,previous=None):
    return {'source':{'format':'v3','authority':'published_v3','generation':1,'snapshot_sequence':0,'sequence':1},
            'completeness':{'classification':'incomplete_prefix' if prefix else 'complete','omitted_range':{'offset':1,'length':1} if prefix and previous is None else None},'previous':previous}


def summary(label,code,command):
    typed=label.startswith('typed-blocked-incompatible');value=origin(code==2,origin(True) if label=='reexport-incomplete' else None)
    if typed or label.startswith('original-v2'):value['source']={'format':'v2','authority':'original_v2','generation':None,'snapshot_sequence':None,'sequence':None}
    return {'schema_version':1,'command':command,'classification':'complete' if code==0 else 'incomplete_prefix','restart_compatibility':'not_evaluated',
            'origin':value,'byte_count':100,'archive_bytes':200,'sha256':'a'*64,'pending':1,'outbox':3 if typed else 1,'receipts':2 if typed else 1,'contributions':1,'blocked':typed}


def report():
    rows=[]
    for role in ('minimum','latest'):
        row={'role':role,'status':'pass','image':gate.runtime.P['logstash.'+role+'.image'],'network':'none','cases':[], 'adoptions':[]}
        for key in ('independent_full_state','isolated_copy_full_state','types_order','read_only_source','unprivileged_owner','schemas_validated',
                    'parent_ack_tls_unchanged','no_checkout','no_compiler_at_runtime','no_python_at_runtime'):row[key]=True
        for label,(code,command) in gate.EXPECTED.items():
            for _ in range(2 if label=='reexport-incomplete' else 1):row['cases'].append({'case':label,'exit_code':code,'inventory_unchanged':True,'summary':summary(label,code,command) if command else None})
        for label in ('published-v3','original-v2','short-header','short-payload'):
            row['adoptions'].append({'case':label,'original_ids':['retained'],'finalized_ids':['retained','continued'],
                **{key:True for key in ('compatible_adoption','continuation','drained','preserved_ids','sender_order','retry_suppression')}})
        rows.append(row)
    return {'status':'pass','artifact':{'sha256':'artifact'},'validators':'validators','runs':rows}


class RecoveryQualificationTest(unittest.TestCase):
    def valid(self,value):return gate.valid(value,{'sha256':'artifact'},'validators')

    def test_every_expected_exit_code_and_negative_summary_is_checked(self):
        good=report();self.assertTrue(self.valid(good))
        for index,case in enumerate(good['runs'][0]['cases']):
            with self.subTest(case=case['case']):
                bad=copy.deepcopy(good);bad['runs'][0]['cases'][index]['exit_code']=5 if case['exit_code']==0 else 0
                self.assertFalse(self.valid(bad))
                bad=copy.deepcopy(good);bad['runs'][0]['cases'][index]['summary']=None if case['summary'] else summary('published-v3',0,'export')
                self.assertFalse(self.valid(bad))

    def test_success_fields_pairing_and_provenance_are_not_bare_pass_flags(self):
        good=report();index=next(i for i,case in enumerate(good['runs'][0]['cases']) if case['case']=='published-v3')
        for key,value in [('blocked',True),('pending',True),('outbox',0),('receipts',0),('contributions',0),('byte_count',False),
                          ('sha256','not-a-digest'),('archive_bytes',100),('command','rebuild'),('classification','incomplete_prefix'),('origin',{}),('schema_version',True)]:
            bad=copy.deepcopy(good);bad['runs'][0]['cases'][index]['summary'][key]=value
            self.assertFalse(self.valid(bad),key)
        for key in good['runs'][0]['cases'][index]['summary']:
            bad=copy.deepcopy(good);del bad['runs'][0]['cases'][index]['summary'][key];self.assertFalse(self.valid(bad),key)
        bad=copy.deepcopy(good);bad['runs'][0]['cases'][index]['summary']['byte_count']=101;self.assertFalse(self.valid(bad),'export/rebuild mismatch')
        for remove in (True,False):
            bad=copy.deepcopy(good)
            if remove:bad['runs'][0]['cases'].pop()
            else:bad['runs'][0]['cases'].append(copy.deepcopy(bad['runs'][0]['cases'][0]))
            self.assertFalse(self.valid(bad))
        bad=copy.deepcopy(good);bad['runs'][0]['adoptions'][0]['retry_suppression']=False;self.assertFalse(self.valid(bad))
        bad=copy.deepcopy(good);bad['runs'][0]['adoptions'][0]['finalized_ids']=['changed','continued'];self.assertFalse(self.valid(bad))
        bad=copy.deepcopy(good);bad['runs'][0]['adoptions'].pop();self.assertFalse(self.valid(bad))
        bad=copy.deepcopy(good);next(case for case in bad['runs'][0]['cases'] if case['case']=='reexport-incomplete')['summary']['origin']['previous']['source']['generation']=2
        self.assertFalse(self.valid(bad),'re-export history must match the tested prefix')

    def test_fresh_linux_proof_requires_exact_current_inventory_and_passing_hashed_xml(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'src/test/java/org/logstashplugins/hec/S2SAssemblyRecoveryTest.java';source.parent.mkdir(parents=True)
            source.write_text('@Test void first(){}\n@Test void second(){}\n')
            xml=root/'results.xml';xml.write_text('<testsuite tests="2" failures="0" errors="0" skipped="0"><testcase name="first()"/><testcase name="second()"/></testsuite>')
            proof={'status':'pass','artifact':{'sha256':'artifact'},'validators':'validators','source_sha256':'source',
                'recovery':{'tests':2,'cases':['first()','second()'],'xml':'results.xml','sha256':hashlib.sha256(xml.read_bytes()).hexdigest()}}
            with patch.object(gate.runtime,'ROOT',root),patch.object(gate.linux_inspection_tests,'source_digest',return_value='source'):
                self.assertTrue(gate.linux_valid(proof,{'sha256':'artifact'},'validators'))
                bad=copy.deepcopy(proof);bad['recovery']['cases']=['first()','stale()'];self.assertFalse(gate.linux_valid(bad,{'sha256':'artifact'},'validators'))
                bad=copy.deepcopy(proof);bad['recovery']['tests']=10;self.assertFalse(gate.linux_valid(bad,{'sha256':'artifact'},'validators'))
                source.write_text(source.read_text()+'@Test void newlyAdded(){}');self.assertFalse(gate.linux_valid(proof,{'sha256':'artifact'},'validators'))
                source.write_text('@Test void first(){}\n@Test void second(){}\n')
                xml.write_text(xml.read_text().replace('skipped="0"','skipped="1"'));proof['recovery']['sha256']=hashlib.sha256(xml.read_bytes()).hexdigest()
                self.assertFalse(gate.linux_valid(proof,{'sha256':'artifact'},'validators'))

    def test_published_origin_schema_bounds_and_describes_every_previous_object(self):
        # Exercise the schema emitted by current compiled production classes, not a hand-copied schema.
        cp=os.pathsep.join(str(ROOT/path) for path in ('build/classes/java/main','vendor/jars/*','.cache/logstash-jars/*'))
        result=subprocess.run(['java','-cp',cp,'org.logstashplugins.hec.S2SAssemblyRecovery','--help','--json'],check=True,capture_output=True,text=True,timeout=20)
        schema=json.loads(result.stdout)['output_schema']['properties']['origin']
        allowed=origin()
        for _ in range(16):allowed=origin(previous=allowed)
        validate(schema,allowed)
        for bad in (origin(previous={}),origin(previous={'secret':True}),origin(previous=allowed)):
            with self.assertRaises(ValueError):validate(schema,bad)
        bad=copy.deepcopy(allowed);bad['previous']['source']['generation']='1'
        with self.assertRaises(ValueError):validate(schema,bad)
        bad=copy.deepcopy(allowed);bad['previous']['completeness']['extra']=True
        with self.assertRaises(ValueError):validate(schema,bad)


if __name__=='__main__':unittest.main()
