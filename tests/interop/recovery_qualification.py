#!/usr/bin/env python3
"""Exact-gem installed recovery; independent raw/tag decoding and isolated-copy oracles."""
import copy
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import uuid
import assembly_state
import runtime
from inspection_contract import validate
from inspection_qualification import inventory, wrap, transaction
from journal_qualification import unpack

REQUIRED={'published-v3','original-v2','typed-blocked-incompatible','short-header','short-payload','reexport-incomplete',
          'complete-corrupt','no-authority','archive-tampered','archive-existing','directory-existing','symlink',
          'fifo','locked','shared-lock','read-only-owner','missing-runtime'}


def archive_read(path):
    """Independent schema/digest/ordered-tag oracle; does not call production Java."""
    value=assembly_state.loads(path.read_bytes())
    assert set(value)=={'schema_version','byte_count','sha256','payload'} and value['schema_version']==1
    payload=value['payload'];assert set(payload)=={'origin','state'}
    covered=json.dumps(payload,ensure_ascii=False,separators=(',',':')).encode()
    assert len(covered)==value['byte_count'] and hashlib.sha256(covered).hexdigest()==value['sha256']
    assembly_state.validate(payload['state'])
    return value


def same(expected,actual):
    assert actual==expected
    for field in ('pending','receipts'):assert list(actual[field])==list(expected[field])
    assert [item['id'] for item in actual['outbox']]==[item['id'] for item in expected['outbox']]
    # Validation includes every native tag; retain its type and exact textual representation.
    for item in actual['outbox']:assembly_state.tagged(item['envelope'])


def main():
    artifact=runtime.artifact_info();validators=runtime.validators_info();run_id=uuid.uuid4().hex
    work=runtime.ROOT/'build/recovery'/run_id;work.mkdir(parents=True)
    probes=work/'probes';probes.mkdir();jar=unpack(runtime.GEM,work/'new')
    subprocess.run(['javac','--release','21','-cp',str(jar)+':'+str(runtime.ROOT/'.cache/logstash-jars')+'/*','-d',str(probes),
                    *[str(runtime.ROOT/'tests/interop'/name) for name in ('JournalProbe.java','InspectionProbe.java','RecoveryProbe.java')]],check=True,timeout=60)
    report={'artifact':artifact,'validators':validators,'run_id':run_id,'status':'fail','runs':[]}
    try:
        for role in ('minimum','latest'):
            name='hec-recovery-'+uuid.uuid4().hex;image=name+':local';fixtures=work/role;fixtures.mkdir()
            build=work/(role+'-build');build.mkdir();shutil.copyfile(runtime.GEM,build/'plugin.gem')
            (build/'Dockerfile').write_text('FROM '+runtime.P['logstash.'+role+'.image']+'\nCOPY --chown=logstash:logstash plugin.gem /tmp/plugin.gem\nRUN bin/logstash-plugin install /tmp/plugin.gem && rm /tmp/plugin.gem\n')
            row={'role':role,'image':runtime.P['logstash.'+role+'.image'],'status':'fail','cases':[],'adoptions':[]};report['runs'].append(row)
            built=started=False;primary=None
            try:
                runtime.docker('build','-t',image,str(build),timeout=900);built=True
                runtime.docker('run','-d','--name',name,'--read-only','--network','none','--user','root','-w','/tmp',
                    '-v',str(fixtures)+':/fixtures','-v',str(fixtures)+':/readonly:ro','-v',str(probes)+':/probes:ro',
                    '--entrypoint','/bin/sleep',image,'1800');started=True
                launcher=runtime.docker('exec',name,'/bin/sh','-c','for p in /usr/share/logstash/vendor/local_gems/*/*/lib/splunk-hec-recover; do [ -f "$p" ] && printf "%s\\n" "$p"; done')
                assert len(launcher.splitlines())==1
                plugin=str(Path(launcher).parent.parent/'vendor/jars'/('logstash-input-splunk_hec-'+runtime.VERSION+'.jar'))
                cp='/probes:'+plugin+':/usr/share/logstash/logstash-core/lib/jars/*'
                def java(main,*args,user=None):
                    return runtime.docker('exec',*(['--user',user] if user else []),name,'/usr/share/logstash/jdk/bin/java','-cp',cp,'org.logstashplugins.hec.'+main,*args)
                java('JournalProbe','seed','/fixtures/seed');seed=fixtures/'seed';state=assembly_state.read(seed)
                outputs=fixtures/'outputs';outputs.mkdir(mode=0o700)
                (fixtures/'ack-high-water').write_text('unchanged-high-water-123456')
                (fixtures/'tls-identity').write_bytes(b'unchanged-identity')
                external={key:(fixtures/key).read_bytes() for key in ('ack-high-water','tls-identity')}
                uid=runtime.docker('exec',name,'id','-u','logstash');gid=runtime.docker('exec',name,'id','-g','logstash');user=uid+':'+gid
                def own():runtime.docker('exec',name,'/bin/sh','-c','chown -R "$1:$2" /fixtures; chmod 700 /fixtures /fixtures/outputs','owner',uid,gid)
                own()
                contract=json.loads(runtime.docker('exec','--user',user,name,'/bin/sh',launcher,'--help','--json'))
                def invoke(label,args,expected,source=None,env=()):
                    before=inventory(source) if source else None
                    result=subprocess.run(['docker','exec','--user',user,*env,name,'/bin/sh',launcher,*args,'--json'],capture_output=True,text=True,timeout=30)
                    assert result.returncode==expected,(label,result.returncode,result.stdout,result.stderr)
                    if source:assert inventory(source)==before,label
                    summary=json.loads(result.stdout) if result.stdout else None
                    if summary:validate(contract['output_schema'],summary)
                    if result.stderr:validate(contract['error_schema'],json.loads(result.stderr))
                    if expected in (0,2):assert summary and summary['restart_compatibility']=='not_evaluated'
                    else:assert not result.stdout
                    assert 'START queued' not in result.stdout+result.stderr and 'private-native' not in result.stdout+result.stderr
                    assert all((fixtures/key).read_bytes()==value for key,value in external.items())
                    row['cases'].append({'case':label,'exit_code':result.returncode,'inventory_unchanged':True,'summary':summary})
                    return summary
                def roundtrip(label,source,expected_state,status=0):
                    archive=outputs/(label+'.archive');target=outputs/(label+'-rebuilt')
                    summary=invoke(label,['export','--assembly-directory','/readonly/'+source.name,'--output','/fixtures/outputs/'+archive.name],status,source)
                    saved=archive_read(archive);same(expected_state,saved['payload']['state'])
                    invoke(label+'-rebuild',['rebuild','--archive','/readonly/outputs/'+archive.name,'--assembly-directory','/fixtures/outputs/'+target.name],status,archive)
                    same(expected_state,assembly_state.read(target));assert (target/'journal-v3-1').read_bytes()==b''
                    assert assembly_state.checked(target/'current-v3')['sequence']==0
                    assert target.stat().st_mode&0o777==0o700 and archive.stat().st_mode&0o777==0o600
                    assert all(path.stat().st_mode&0o777==0o600 for path in target.iterdir())
                    isolated=outputs/(label+'-copy');shutil.copytree(target,isolated);own()
                    same(expected_state,assembly_state.loads(java('RecoveryProbe','/fixtures/outputs/'+isolated.name,user=user)))
                    if expected_state['configuration']==state['configuration'] and not expected_state['blocked']:
                        adopted=outputs/(label+'-adoption');shutil.copytree(target,adopted);own()
                        proof=json.loads(java('RecoveryProbe','adopt','/fixtures/outputs/'+adopted.name,user=user))
                        assert all(proof[key] is True for key in ('compatible_adoption','continuation','drained','preserved_ids','sender_order','retry_suppression'))
                        assert proof['original_ids']==[item['id'] for item in expected_state['outbox']]
                        assert proof['finalized_ids'][:len(proof['original_ids'])]==proof['original_ids']
                        assert all((fixtures/key).read_bytes()==value for key,value in external.items())
                        row['adoptions'].append({'case':label,**proof})
                    assert java('InspectionProbe','released','/readonly/'+source.name,user=user)=='released'
                    return archive,target,summary
                roundtrip('published-v3',seed,state)
                legacy=fixtures/'legacy';legacy.mkdir(mode=0o700);(legacy/'lock').write_bytes(b'');(legacy/'state').write_bytes(wrap(state));own()
                roundtrip('original-v2',legacy,state)
                typed=copy.deepcopy(state);typed['blocked']=True;typed['configuration']='incompatible-preserved-fingerprint'
                values={'map':[['negative-zero',{'number':['Double','-0.0']}],['decimal',{'number':['BigDecimal','123.45000']}],
                    ['large',{'number':['BigInteger','123456789012345678901234567890']}],['integer',{'number':['Integer','7']}],['long',{'number':['Long','9']}],
                    ['timestamp',{'timestamp':'2023-11-14T22:13:20.123456789Z'}],['list',{'list':[True,None,'private-native']}]]}
                typed['outbox']=[{'id':str(uuid.uuid4()),'envelope':values,'sender':'retained-sender'} for _ in range(3)]
                typed['receipts']={'b'*64:'a'*64,'a'*64:'b'*64}
                typed_path=fixtures/'typed';typed_path.mkdir(mode=0o700);(typed_path/'lock').write_bytes(b'');(typed_path/'state').write_bytes(wrap(typed));own()
                roundtrip('typed-blocked-incompatible',typed_path,typed)
                empty={'configuration':state['configuration'],'removePending':[],'pending':[],'removeOutputs':[],'outputs':[],'removeReceipts':[],'receipts':{},'receiptOrder':None,'pendingOrder':None,'blocked':True}
                pointer=assembly_state.checked(seed/'current-v3');original=assembly_state.journal_path(seed).read_bytes()
                # Seed has one journal transaction; independently read its ordinal.
                import struct
                sequence=pointer['sequence'];position=0
                while position<len(original):
                    _,_,sequence,length=struct.unpack('>IIQQ',original[position:position+24]);position+=88+length
                for label,suffix in [('short-header',b'torn'),('short-payload',transaction(sequence+1,empty)[:-1])]:
                    path=fixtures/label;shutil.copytree(seed,path);journal=assembly_state.journal_path(path);journal.write_bytes(original+suffix);own()
                    archive,target,summary=roundtrip(label,path,state,2)
                    assert summary['origin']['completeness']['omitted_range']=={'offset':len(original),'length':len(suffix)}
                    second=outputs/(label+'-again.archive')
                    invoke('reexport-incomplete',['export','--assembly-directory','/readonly/outputs/'+target.name,'--output','/fixtures/outputs/'+second.name],2,target)
                    assert archive_read(second)['payload']['origin']['previous']==archive_read(archive)['payload']['origin']
                bad=fixtures/'bad';shutil.copytree(seed,bad);journal=assembly_state.journal_path(bad);journal.write_bytes(original[:-1]+bytes([original[-1]^1]));own()
                invoke('complete-corrupt',['export','--assembly-directory','/readonly/bad','--output','/fixtures/outputs/bad.archive'],3,bad)
                no_authority=fixtures/'no-authority';shutil.copytree(seed,no_authority);(no_authority/'current-v3').unlink();(no_authority/'backup-v2').write_bytes(wrap(state));own()
                invoke('no-authority',['export','--assembly-directory','/readonly/no-authority','--output','/fixtures/outputs/no-authority.archive'],3,no_authority)
                for label,prepare in [('symlink',lambda path:(path/'stray').symlink_to('state')),('fifo',lambda path:os.mkfifo(path/'fifo'))]:
                    path=fixtures/label;shutil.copytree(seed,path);prepare(path);own()
                    invoke(label,['export','--assembly-directory','/readonly/'+label,'--output','/fixtures/outputs/'+label+'.archive'],5,path)
                invoke('archive-existing',['export','--assembly-directory','/readonly/seed','--output','/fixtures/outputs/published-v3.archive'],5,seed)
                invoke('directory-existing',['rebuild','--archive','/readonly/outputs/published-v3.archive','--assembly-directory','/fixtures/outputs/published-v3-rebuilt'],5,outputs/'published-v3.archive')
                tampered=outputs/'tampered.archive';bad_archive=json.loads((outputs/'published-v3.archive').read_bytes());bad_archive['payload']['state']['blocked']=True;tampered.write_text(json.dumps(bad_archive));own()
                invoke('archive-tampered',['rebuild','--archive','/readonly/outputs/tampered.archive','--assembly-directory','/fixtures/outputs/tampered-rebuilt'],3,tampered)
                assert not (outputs/'tampered-rebuilt').exists()
                for mode,expected in [('exclusive',4),('shared',0)]:
                    peer=subprocess.Popen(['docker','exec',name,'/usr/share/logstash/jdk/bin/java','-cp',cp,'org.logstashplugins.hec.InspectionProbe','lock','/fixtures/seed',mode],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                    pid=None
                    try:
                        assert select.select([peer.stdout],[],[],20)[0];ready=peer.stdout.readline().split();assert ready[0]=='ready';pid=ready[1];assert pid.isdigit()
                        invoke('locked' if expected==4 else 'shared-lock',['export','--assembly-directory','/readonly/seed','--output','/fixtures/outputs/'+mode+'.archive'],expected,seed)
                    finally:
                        if pid:runtime.docker('exec',name,'/bin/sh','-c','kill -TERM "$1"','lock-peer',pid)
                        peer.wait(timeout=10)
                assert java('InspectionProbe','write-refused','/readonly/seed',user=user)=='read-only'
                invoke('read-only-owner',['export','--assembly-directory','/readonly/seed','--output','/fixtures/outputs/owner.archive'],0,seed)
                invoke('missing-runtime',['--help'],70,env=('-e','LOGSTASH_HOME=/absent-private-runtime'))
                assert {case['case'] for case in row['cases']}>=REQUIRED
                row.update(status='pass',independent_full_state=True,isolated_copy_full_state=True,types_order=True,read_only_source=True,unprivileged_owner=True,
                    schemas_validated=True,parent_ack_tls_unchanged=True,no_checkout=True,no_compiler_at_runtime=True,no_python_at_runtime=True,network='none',installed_launcher=launcher)
                print('PASS installed recovery',role,len(row['cases']),'cases',flush=True)
            except BaseException as error:primary=error;raise
            finally:
                for owned,command in [(started,['docker','rm','-f','-v',name]),(built,['docker','image','rm',image])]:
                    if not owned:continue
                    try:subprocess.run(command,check=True,capture_output=True,text=True,timeout=60)
                    except BaseException as cleanup:
                        row['status']='fail'
                        if primary is None:raise
                        primary.add_note('owned cleanup failed: '+str(cleanup))
        assert runtime.artifact_info()==artifact and runtime.validators_info()==validators
        report['status']='pass'
    except BaseException as error:
        report['error']={'type':type(error).__name__,'message':str(error),'stdout':getattr(error,'stdout',None),'stderr':getattr(error,'stderr',None)}
        raise
    finally:(runtime.EVIDENCE/'recovery.json').write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':main()
