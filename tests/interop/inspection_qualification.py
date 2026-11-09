#!/usr/bin/env python3
"""Exact-gem installed diagnostics qualification, isolated from checkout runtime paths."""
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import stat
import struct
import subprocess
import uuid
import runtime
import assembly_state
from inspection_contract import validate
from journal_qualification import unpack

BASELINE=runtime.ROOT/'logstash-input-splunk_hec-0.3.0-java.gem'
BASELINE_SHA256='ebb1379e32808445f80f1238801742d2d400ebd9a0b46e3673d0e6d535e0cf9a'

def inventory(path):
    if not path.exists():return {}
    result={}
    for entry in [path,*sorted(path.rglob('*'))]:
        info=entry.lstat()
        digest=hashlib.sha256(entry.read_bytes()).hexdigest() if stat.S_ISREG(info.st_mode) else os.readlink(entry) if stat.S_ISLNK(info.st_mode) else None
        result[str(entry.relative_to(path))]={'mode':info.st_mode,'mtime_ns':info.st_mtime_ns,'bytes':info.st_size,'sha256':digest}
    return result

def wrap(value):
    payload=json.dumps(value,separators=(',',':')).encode()
    return hashlib.sha256(payload).hexdigest().encode()+b'\n'+payload

def transaction(sequence,value):
    payload=json.dumps(value,separators=(',',':')).encode();prefix=struct.pack('>IIQQ',0x53325333,3,sequence,len(payload))
    return prefix+hashlib.sha256(prefix).digest()+hashlib.sha256(payload).digest()+payload

def main():
    artifact=runtime.artifact_info();validators=runtime.validators_info()
    if hashlib.sha256(BASELINE.read_bytes()).hexdigest()!=BASELINE_SHA256:raise RuntimeError('0.3.0 baseline identity mismatch')
    run_id=uuid.uuid4().hex;work=runtime.ROOT/'build/inspection'/run_id;work.mkdir(parents=True)
    probes=work/'probes';probes.mkdir();new=unpack(runtime.GEM,work/'new');old=unpack(BASELINE,work/'old')
    subprocess.run(['javac','--release','21','-cp',str(new)+':'+str(runtime.ROOT/'.cache/logstash-jars')+'/*','-d',str(probes),
                    str(runtime.ROOT/'tests/interop/JournalProbe.java'),str(runtime.ROOT/'tests/interop/InspectionProbe.java')],check=True,timeout=60)
    report={'artifact':artifact,'validators':validators,'run_id':run_id,'baseline':{'sha256':BASELINE_SHA256,'file':BASELINE.name},'status':'fail','runs':[]}
    try:
        for role in ('minimum','latest'):
            name='hec-inspection-'+uuid.uuid4().hex;image=name+':local';directory=work/role;directory.mkdir();build=work/(role+'-build');build.mkdir()
            shutil.copyfile(runtime.GEM,build/'plugin.gem')
            (build/'Dockerfile').write_text('FROM '+runtime.P['logstash.'+role+'.image']+'\nCOPY --chown=logstash:logstash plugin.gem /tmp/plugin.gem\nRUN bin/logstash-plugin install /tmp/plugin.gem && rm /tmp/plugin.gem\n')
            row={'role':role,'image':runtime.P['logstash.'+role+'.image'],'cases':[],'status':'fail'};report['runs'].append(row)
            built=False;started=False;primary=None
            volume=name+'-owner'
            volume_created=False
            try:
                runtime.docker('build','-t',image,str(build),timeout=900)
                built=True
                runtime.docker('volume','create','--label','org.logstash.hec.inspection-run='+run_id,volume)
                volume_created=True
                runtime.docker('run','-d','--name',name,'--read-only','--network','none','--user','root','-w','/tmp',
                    '-v',str(directory)+':/fixtures','-v',str(probes)+':/probes:ro','-v',str(old)+':/baseline.jar:ro',
                    '-v',volume+':/owner','-v',volume+':/readonly-owner:ro',
                    '--entrypoint','/bin/sleep',image,'1800')
                started=True
                launcher=runtime.docker('exec',name,'/bin/sh','-c','for p in /usr/share/logstash/vendor/local_gems/*/*/lib/splunk-hec-inspect; do [ -f "$p" ] && printf "%s\\n" "$p"; done')
                if len(launcher.splitlines())!=1:raise RuntimeError('ambiguous installed launcher')
                plugin=str(Path(launcher).parent.parent/'vendor/jars'/('logstash-input-splunk_hec-'+runtime.VERSION+'.jar'))
                contract=json.loads(runtime.docker('exec',name,'/bin/sh',launcher,'--help','--json'))
                classpath='/probes:'+plugin+':/usr/share/logstash/logstash-core/lib/jars/*'
                def java(main,*args,baseline=False):
                    cp='/probes:/baseline.jar:/usr/share/logstash/logstash-core/lib/jars/*' if baseline else classpath
                    return runtime.docker('exec',name,'/usr/share/logstash/jdk/bin/java','-cp',cp,'org.logstashplugins.hec.'+main,*args)
                java('JournalProbe','seed','/fixtures/seed',baseline=True)
                seed=directory/'seed';state=assembly_state.read(seed)
                def clone(label):
                    path=directory/label;shutil.copytree(seed,path);return path
                def invoke(label,path,expected,*extra):
                    before=inventory(path)
                    command=['docker','exec','-i',name,'/bin/sh',launcher,'--assembly-directory','/fixtures/'+path.name,'--json',*extra]
                    result=subprocess.run(command,text=True,capture_output=True,timeout=30)
                    assert inventory(path)==before,'changed inventory: '+label
                    assert result.returncode==expected,(label,result.returncode,result.stdout,result.stderr)
                    summary=json.loads(result.stdout) if result.stdout else None
                    if summary is not None:validate(contract['output_schema'],summary)
                    if result.stderr:validate(contract['warning_schema'] if expected==2 else contract['error_schema'],json.loads(result.stderr))
                    if expected in (0,2):assert summary['restart_compatibility']=='not_evaluated'
                    else:assert not result.stdout and 'error' in json.loads(result.stderr)
                    assert 'START queued' not in result.stdout+result.stderr and 'START pending' not in result.stdout+result.stderr
                    item={'case':label,'exit_code':result.returncode,'inventory_unchanged':True,'stdout':summary,'stderr':result.stderr};row['cases'].append(item)
                    return summary
                summary=invoke('published-v3',seed,0)
                for key,value in {'pending':len(state['pending']),'outbox':len(state['outbox']),'receipts':len(state['receipts']),'blocked':state['blocked'],
                                  'contributions':sum(len(p['contributions']) for p in state['pending'].values())}.items():assert summary[key]==value
                copy=clone('production-copy');recovered=json.loads(java('InspectionProbe','recover','/fixtures/'+copy.name).splitlines()[-1])
                assert all(summary[key]==value for key,value in recovered.items());row['production_copy_matches']=True;row['independent_oracle_matches']=True
                legacy=directory/'legacy';legacy.mkdir(mode=0o700);(legacy/'lock').write_bytes(b'');(legacy/'state').write_bytes(wrap(state));invoke('original-v2',legacy,0)
                blocked=clone('blocked');pointer=assembly_state.checked(blocked/'current-v3');snap=assembly_state.checked(blocked/('snapshot-v3-'+str(pointer['generation'])))
                empty={'configuration':state['configuration'],'removePending':[],'pending':[],'removeOutputs':[],'outputs':[],'removeReceipts':[],'receipts':{},'receiptOrder':None,'pendingOrder':None,'blocked':True}
                journal=assembly_state.journal_path(blocked);journal.write_bytes(journal.read_bytes()+transaction(summary['sequence']+1,empty));assert invoke('persisted-blocked',blocked,0)['blocked'] is True
                for label,suffix in [('short-header',b'x'*17),('short-authenticated-payload',transaction(summary['sequence']+1,empty)[:-1])]:
                    path=clone(label);journal=assembly_state.journal_path(path);journal.write_bytes(journal.read_bytes()+suffix);torn=invoke(label,path,2)
                    assert torn['sequence']==summary['sequence'] and torn['incomplete_suffix']['length']==len(suffix)
                    recovery=directory/(label+'-recovery');shutil.copytree(path,recovery)
                    recovered=json.loads(java('InspectionProbe','recover','/fixtures/'+recovery.name).splitlines()[-1])
                    assert all(torn[key]==value for key,value in recovered.items())
                compacted=clone('compacted')
                java('InspectionProbe','compact','/fixtures/'+compacted.name)
                java('InspectionProbe','append','/fixtures/'+compacted.name)
                compact_state=assembly_state.read(compacted)
                for torn in (False,True):
                    if torn:
                        journal=assembly_state.journal_path(compacted);journal.write_bytes(journal.read_bytes()+b'torn')
                    compact_summary=invoke('compacted-torn' if torn else 'compacted-v3',compacted,2 if torn else 0)
                    assert compact_summary['generation']>=2 and compact_summary['snapshot_sequence']>0
                    for key,value in {'pending':len(compact_state['pending']),'outbox':len(compact_state['outbox']),
                        'receipts':len(compact_state['receipts']),'contributions':sum(len(p['contributions']) for p in compact_state['pending'].values())}.items():assert compact_summary[key]==value
                    copy=directory/('compacted-recovery-'+str(torn));shutil.copytree(compacted,copy)
                    recovered=json.loads(java('InspectionProbe','recover','/fixtures/'+copy.name).splitlines()[-1])
                    assert all(compact_summary[key]==value for key,value in recovered.items())
                row['compacted_and_torn_recovery_match']=True
                for label,mutation in [('checksum',lambda b:b[:-1]+bytes([b[-1]^1])),('bad-complete-header',lambda b:bytes([b[0]^1])+b[1:])]:
                    path=clone(label);journal=assembly_state.journal_path(path);journal.write_bytes(mutation(journal.read_bytes()));invoke(label,path,3)
                path=clone('bad-operation');bad=dict(empty,removePending=['missing']);journal=assembly_state.journal_path(path);journal.write_bytes(journal.read_bytes()+transaction(summary['sequence']+1,bad));invoke('authenticated-bad-operation',path,3)
                path=clone('no-pointer');(path/'current-v3').unlink();(path/'backup-v2').write_bytes(wrap(state));ambiguous=invoke('ambiguous-publication',path,2);assert ambiguous['authority']=='none' and 'pending' not in ambiguous
                path=clone('no-lock');(path/'lock').unlink();invoke('missing-lock',path,5)
                path=clone('symlink');(path/'stray').symlink_to('state');invoke('symlink-entry',path,5)
                path=clone('fifo');os.mkfifo(path/'fifo');invoke('special-file',path,5)
                path=clone('public');path.chmod(0o755);invoke('public-directory',path,5)
                path=clone('budget');[(path/('extra-'+str(i))).write_bytes(b'') for i in range(257)];invoke('entry-budget',path,5)
                for mode,expected in [('exclusive',4),('shared',0)]:
                    holder=subprocess.Popen(['docker','exec',name,'/usr/share/logstash/jdk/bin/java','-cp',classpath,'org.logstashplugins.hec.InspectionProbe','lock','/fixtures/seed',mode],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                    pid=None
                    try:
                        if not select.select([holder.stdout],[],[],20)[0]:raise RuntimeError('Java lock peer readiness timeout')
                        ready=holder.stdout.readline().strip().split();assert ready[0]=='ready';pid=ready[1];assert pid.isdigit();invoke('java-'+mode+'-lock',seed,expected)
                    finally:
                        # Container exec clients do not own the Java child's lifetime. Explicitly stop that exact class.
                        if pid:runtime.docker('exec',name,'/bin/sh','-c','kill -TERM "$1"','inspection-lock',pid)
                        holder.wait(timeout=10)
                help_result=json.loads(runtime.docker('exec',name,'/bin/sh',launcher,'--help','--json'));assert help_result['schema_version']==1
                # The service UID owns this Linux volume. A separate mount exposes
                # exactly that data read-only; this is not merely a read-only rootfs.
                uid=runtime.docker('exec',name,'id','-u','logstash')
                gid=runtime.docker('exec',name,'id','-g','logstash')
                assert uid.isdigit() and gid.isdigit() and uid!='0'
                runtime.docker('exec',name,'/bin/sh','-c','cp -a /fixtures/seed /owner/spool && chown -R "$1:$2" /owner/spool','owner-fixture',uid,gid)
                def owner_java(action):
                    return runtime.docker('exec','--user',uid+':'+gid,name,'/usr/share/logstash/jdk/bin/java','-cp',classpath,
                        'org.logstashplugins.hec.InspectionProbe',action,'/readonly-owner/spool')
                assert owner_java('write-refused')=='read-only'
                owner_before=json.loads(owner_java('inventory'))
                owned=subprocess.run(['docker','exec','--user',uid+':'+gid,name,'/bin/sh',launcher,'--assembly-directory','/readonly-owner/spool','--json'],capture_output=True,text=True,timeout=30)
                assert owned.returncode==0,(owned.stdout,owned.stderr)
                validate(contract['output_schema'],json.loads(owned.stdout))
                assert json.loads(owner_java('inventory'))==owner_before
                assert owner_java('released')=='released'
                # The owner can chmod via the writable alias solely to prepare
                # this unreadable fixture; the command receives the read-only alias.
                runtime.docker('exec',name,'chmod','000','/owner/spool/current-v3')
                denied=subprocess.run(['docker','exec','--user',uid+':'+gid,name,'/bin/sh',launcher,'--assembly-directory','/readonly-owner/spool','--json'],capture_output=True,text=True,timeout=30)
                assert denied.returncode==5 and not denied.stdout,denied
                validate(contract['error_schema'],json.loads(denied.stderr))
                assert owner_java('released')=='released'
                runtime.docker('exec',name,'chmod','600','/owner/spool/current-v3')
                assert json.loads(owner_java('inventory'))==owner_before
                row.update(unprivileged_owner=True,read_only_spool_mount=True,unreadable_owner_file_refused=True,
                    schema_outputs_validated=True,owner_uid=int(uid))
                row.update(status='pass',installed_launcher=launcher,no_checkout=True,no_python=True,no_compiler_at_runtime=True,network='none',read_only_root=True)
                print('PASS installed inspection',role,len(row['cases']),'cases',flush=True)
            except BaseException as error:
                primary=error;raise
            finally:
                for owned,command in [(started,['docker','rm','-f','-v',name]),(built,['docker','image','rm',image]),(volume_created,['docker','volume','rm',volume])]:
                    if not owned:continue
                    try:subprocess.run(command,capture_output=True,text=True,timeout=60,check=True)
                    except BaseException as cleanup:
                        row['status']='fail'
                        if primary is None:raise
                        primary.add_note('owned cleanup failed: '+str(cleanup))
        assert runtime.artifact_info()==artifact and runtime.validators_info()==validators
        report['status']='pass'
    except BaseException as error:
        report['error']={'type':type(error).__name__,'message':str(error),'stdout':getattr(error,'stdout',None),'stderr':getattr(error,'stderr',None)}
        raise
    finally:
        (runtime.EVIDENCE/'inspection.json').write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':main()
