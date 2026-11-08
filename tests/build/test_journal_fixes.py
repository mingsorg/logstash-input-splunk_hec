"""Focused malformed controls, cleanup and review identity regressions."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests/interop'))
import assembly_state as state
import journal_qualification as journal
import review_journal as review
import check_assembly_qualification as gate

class JournalFixesTest(unittest.TestCase):
    def test_concurrent_progress_requires_multiple_real_retained_contributions(self):
        row=dict(lines=500,producer_actual_contributions=2,producer_contribution_cap=32,retained_contributions_after_progress=502,contribution_limit=10000,concurrent_unrelated_sender_ns=1000)
        self.assertTrue(gate.real_growth_progress(row))
        for changes in ({'producer_actual_contributions':1,'retained_contributions_after_progress':501},{'retained_contributions_after_progress':500},{'producer_actual_contributions':33},{'concurrent_unrelated_sender_ns':5000000001},{'contribution_limit':10001}):
            self.assertFalse(gate.real_growth_progress(dict(row,**changes)))
    def original(self):
        pending=dict(envelope={'map':[]},text='START',delimiter='',rule='a'*64,chain='b'*64,attributes='c'*64,origin='d'*64,
                     contributions=[{'line':0}],touched=1000,timeout=100,eventLimit=1048576,sender='sender',offset=5,sequence=1)
        return dict(configuration='config',pending={'e'*64:pending},outbox=[dict(id='first',envelope={'map':[]},sender='sender')],receipts={'f'*64:'a'*64},blocked=False)
    def transaction(self):
        return dict(configuration='config',removePending=[],pending=[],removeOutputs=[],outputs=[],removeReceipts=[],receipts={},receiptOrder=None,pendingOrder=None,blocked=False)
    def test_duplicate_keys_and_malformed_operations_fail_closed(self):
        with self.assertRaises(ValueError):state.loads('{"pending":{},"pending":{}}')
        controls=[]
        tx=self.transaction();tx['receipts']={'f'*64:'b'*64};controls.append(tx)
        tx=self.transaction();tx['outputs']=[dict(id='first',envelope={'map':[]},sender='sender')];controls.append(tx)
        tx=self.transaction();tx['outputs']=[dict(id='new',envelope=None,sender=None)];controls.append(tx)
        for field in ('eventLimit','timeout','rule','origin','attributes','sender','envelope','text','contributions'):
            value=copy.deepcopy(self.original()['pending']['e'*64]);value.update(envelope=None,text='',contributions=[])
            value[field]=({'eventLimit':42,'timeout':42,'envelope':{'map':[]},'text':'prefix','contributions':[{}]}).get(field,'changed')
            tx=self.transaction();tx['pending']=[dict(key='e'*64,prior='b'*64,value=value,text='tail',contributions=[{'line':1}])];controls.append(tx)
        for tx in controls:
            with self.subTest(tx=tx),self.assertRaises(ValueError):state.apply(self.original(),tx)
    def test_valid_append_and_order_replay(self):
        original=self.original();value=copy.deepcopy(original['pending']['e'*64]);value.update(envelope=None,text='',contributions=[])
        tx=self.transaction();tx['pending']=[dict(key='e'*64,prior='b'*64,value=value,text='\ntail',contributions=[{'line':1}])]
        result=state.apply(original,tx);self.assertEqual('START\ntail',result['pending']['e'*64]['text']);self.assertEqual('START',original['pending']['e'*64]['text'])
    def test_authenticated_malformed_records_are_not_torn_tails(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
            root=Path(temporary)
            def checked(path,value):
                payload=json.dumps(value).encode();path.write_bytes(hashlib.sha256(payload).hexdigest().encode()+b'\n'+payload);return payload
            payload=checked(root/'snapshot-v3-1',dict(sequence=0,state=self.original()))
            checked(root/'current-v3',dict(generation=1,sequence=0,snapshot=hashlib.sha256(payload).hexdigest()))
            controls=[b'{"configuration":"config","configuration":"other"}']
            tx=self.transaction();tx['receipts']={'f'*64:'b'*64};controls.append(json.dumps(tx).encode())
            tx=self.transaction();tx['outputs']=[dict(id='first',envelope={'map':[]},sender='sender')];controls.append(json.dumps(tx).encode())
            for payload in controls:
                framing=struct.pack('>IIQQ',0x53325333,3,1,len(payload));record=framing+hashlib.sha256(framing).digest()+hashlib.sha256(payload).digest()+payload
                (root/'journal-v3-1').write_bytes(record)
                with self.assertRaises(ValueError):state.read(root)
                self.assertEqual(record,(root/'journal-v3-1').read_bytes())
    def test_cleanup_nonzero_cannot_pass_and_preserves_primary_failure(self):
        cleanup=subprocess.CalledProcessError(1,['docker','rm'],stderr='denied')
        with patch.object(journal.runtime,'docker',return_value='pass'),patch.object(journal.subprocess,'run',side_effect=cleanup):
            with self.assertRaises(subprocess.CalledProcessError):journal.owned_probe('owned',[])
        primary=RuntimeError('run failed')
        with patch.object(journal.runtime,'docker',side_effect=primary),patch.object(journal.subprocess,'run',side_effect=cleanup):
            with self.assertRaises(RuntimeError) as raised:journal.owned_probe('owned',[])
            self.assertIs(primary,raised.exception);self.assertIn('cleanup failed',primary.__notes__[0])
    def review_fixture(self,root,native=False):
        for name in (review.CLAIMS,'VERSION','build.gradle','versions.properties','README.md'):
            path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('claims')
        _,source,claims=review.reviewed_source(root);artifact={'sha256':'artifact'};reports=[]
        for i,lens in enumerate(review.LENSES):
            result=dict(is_error=False,usage={'input_tokens':100},structured_output=dict(lens=lens,source_sha256=source,claims_sha256=claims,artifact_sha256='artifact',verdict='pass',findings=[]))
            if native:
                proof=result['structured_output']
                result=dict(provider='opencode-task',reviewer_session_id=f'test-review-session-{i}',text='Test reviewer final response:\n```json\n'+json.dumps(proof)+'\n```\nNo additional findings.',structured_output=proof)
            path=root/f'report-{i}.json';path.write_text(json.dumps(result));item=dict(lens=lens,file=path.name,sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            if not native:item['exit_code']=0
            reports.append(item)
        return dict(artifact=artifact,validators='validators',source_sha256=source,claims_file=review.CLAIMS,claims_sha256=claims,reports=reports),artifact
    def test_native_task_review_accepts_bound_distinct_sessions_without_cli_usage(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
            root=Path(temporary);identity,artifact=self.review_fixture(root,native=True)
            self.assertTrue(gate.review_complete(identity,artifact,'validators',root))
            for item in identity['reports']:
                result=json.loads((root/item['file']).read_text())
                self.assertNotIn('usage',result);self.assertNotIn('exit_code',item)
            self.assertFalse(gate.review_complete(identity,{'sha256':'stale-artifact'},'validators',root))
            self.assertFalse(gate.review_complete(identity,artifact,'stale-validators',root))
            (root/'README.md').write_text('new source')
            self.assertFalse(gate.review_complete(identity,artifact,'validators',root))
    def test_native_task_review_rejects_stale_proof_duplicate_sessions_and_missing_text(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
            root=Path(temporary);identity,artifact=self.review_fixture(root,native=True)
            original=json.loads((root/'report-1.json').read_text())
            controls=[]
            for field in ('lens','source_sha256','claims_sha256','artifact_sha256','verdict','findings'):
                changed=copy.deepcopy(original);changed['structured_output'][field]=['unresolved finding'] if field=='findings' else 'stale'
                controls.append(changed)
            for session in ('test-review-session-0','',None,'   '):
                controls.append(dict(original,reviewer_session_id=session))
            for text in ('',None,[], '   '):controls.append(dict(original,text=text))
            changed=copy.deepcopy(original);del changed['text'];controls.append(changed)
            controls.append(dict(original,provider='other-provider'))
            for result in controls:
                path=root/'report-1.json';path.write_text(json.dumps(result));identity['reports'][1]['sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
                with self.subTest(result=result):self.assertFalse(gate.review_complete(identity,artifact,'validators',root))
    def test_native_task_raw_response_tamper_is_rejected_by_manifest_hash(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
            root=Path(temporary);identity,artifact=self.review_fixture(root,native=True)
            path=root/'report-0.json';result=json.loads(path.read_text());result['text']='Tampered raw reviewer response'
            path.write_text(json.dumps(result))
            self.assertFalse(gate.review_complete(identity,artifact,'validators',root))
            path.unlink();self.assertFalse(gate.review_complete(identity,artifact,'validators',root))
    def test_native_raw_verdict_must_match_even_with_updated_manifest_hash(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
            root=Path(temporary);identity,artifact=self.review_fixture(root,native=True)
            path=root/'report-0.json';original=json.loads(path.read_text());proof=original['structured_output']
            blocker=dict(proof,verdict='findings',findings=['Blocking durability defect'])
            texts=[
                'Review results:\n```json\n'+json.dumps(blocker)+'\n```\nThis blocker needs a fix.',
                'No JSON verdict here.',
                json.dumps(proof)+'\n'+json.dumps(proof),
                json.dumps(proof)+'\n'+json.dumps(blocker),
                json.dumps(dict(proof,lens='different lens')),
            ]
            for text in texts:
                result=dict(original,text=text);path.write_text(json.dumps(result))
                identity['reports'][0]['sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
                with self.subTest(text=text):self.assertFalse(gate.review_complete(identity,artifact,'validators',root))
            result=dict(original,text='Explanation before '+json.dumps(proof)+' and after.')
            path.write_text(json.dumps(result));identity['reports'][0]['sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertTrue(gate.review_complete(identity,artifact,'validators',root))
    def test_review_rejects_stale_source_duplicate_lenses_paths_and_unhashed_proof(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
            root=Path(temporary);identity,artifact=self.review_fixture(root)
            self.assertTrue(gate.review_complete(identity,artifact,'validators',root))
            for key in ('lens','file'):
                changed=copy.deepcopy(identity);changed['reports'][1][key]=changed['reports'][0][key]
                self.assertFalse(gate.review_complete(changed,artifact,'validators',root))
            changed=copy.deepcopy(identity);changed['source_sha256']='stale';self.assertFalse(gate.review_complete(changed,artifact,'validators',root))
            changed=copy.deepcopy(identity);changed['claims_file']='../external-spec.md';self.assertFalse(gate.review_complete(changed,artifact,'validators',root))
            path=root/'report-0.json';path.write_text(path.read_text()+' ');self.assertFalse(gate.review_complete(identity,artifact,'validators',root))
            identity,artifact=self.review_fixture(root);(root/'README.md').write_text('changed source');self.assertFalse(gate.review_complete(identity,artifact,'validators',root))
    def test_coordinator_assertion_without_bound_reviewer_result_is_not_approval(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
            root=Path(temporary);identity,artifact=self.review_fixture(root);path=root/'report-0.json'
            path.write_text(json.dumps(dict(is_error=False,result='No unresolved high or medium findings',usage={'input_tokens':100})))
            identity['reports'][0]['sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertFalse(gate.review_complete(identity,artifact,'validators',root))
    def test_scalar_array_null_review_reports_fail_closed(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
            root=Path(temporary);identity,artifact=self.review_fixture(root)
            for value in (None,[],42,'pass'):
                path=root/'report-0.json';path.write_text(json.dumps(value));identity['reports'][0]['sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
                self.assertFalse(gate.review_complete(identity,artifact,'validators',root))
                self.assertFalse(gate.review_complete(value,artifact,'validators',root))
    def test_decimal_comparison_preserves_distinct_native_values(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
            root=Path(temporary);left=root/'left.json';right=root/'right.json'
            left.write_text('{"value":1.234567890123456789}');right.write_text('{"value":1.234567890123456788}')
            self.assertNotEqual(journal.native_json(left),journal.native_json(right))
    def test_malformed_tagged_codec_parity(self):
        for value in ({'map':[],'list':[]},{'map':{}},{'map':[['x',1]]},{'map':[['x',None,0]]},{'map':[[1,None]]},{'map':[['x',None],['x',None]]},
                      {'list':None},{'number':['Long','1','extra']},{'number':['Double','NaN']},{'timestamp':0},{'timestamp':'invalid'}):
            with self.subTest(value=value),self.assertRaises((ValueError,TypeError,AttributeError)):state.envelope(value)
    def test_soak_bound_is_independently_derived(self):
        row=dict(quota=8192,events=2000,peak_physical_bytes=98304,transient_publication_samples=10,compactions=1,memory_released=True)
        self.assertTrue(gate.soak_row_valid(row));row.update(peak_physical_bytes=98305,physical_bound=10**12);self.assertFalse(gate.soak_row_valid(row))
        row.update(peak_physical_bytes=100,transient_publication_samples=0);self.assertFalse(gate.soak_row_valid(row))

if __name__=='__main__':unittest.main()
