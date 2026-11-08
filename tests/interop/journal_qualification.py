#!/usr/bin/env python3
"""Fresh packaged-jar migration, scaling and sustained-traffic qualification."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import uuid
import runtime
import assembly_state
from decimal import Decimal

def native_json(path):return json.loads(path.read_text(),parse_float=Decimal)

BASELINE=runtime.ROOT/'logstash-input-splunk_hec-0.2.0-java.gem'
BASELINE_SHA256='3dbc0a7162c10d3c666562b274200cca487f2d96176b683bb8a6f598b06cdc11'

def unpack(gem,output):
    output.mkdir(parents=True)
    with tarfile.open(gem) as package:
        with tarfile.open(fileobj=package.extractfile('data.tar.gz'),mode='r:gz') as data:
            jars=[member for member in data.getmembers() if member.name.startswith('vendor/jars/') and member.name.endswith('.jar')]
            if len(jars)!=1:raise RuntimeError('package must contain one jar')
            path=output/'plugin.jar';path.write_bytes(data.extractfile(jars[0]).read());return path

def owned_probe(name,arguments):
    failure=None
    try:return runtime.docker('run','--name',name,*arguments,timeout=900)
    except BaseException as error:failure=error;raise
    finally:
        try:subprocess.run(['docker','rm','-f',name],capture_output=True,text=True,timeout=60,check=True)
        except BaseException as cleanup:
            if failure is None:raise
            failure.add_note('owned cleanup failed: '+repr(cleanup))

def main():
    artifact=runtime.artifact_info();validators=runtime.validators_info()
    run_id=uuid.uuid4().hex;directory=runtime.ROOT/'tests/interop/evidence'/runtime.VERSION/'journal-runs'/run_id
    directory.mkdir(parents=True)
    new=unpack(runtime.GEM,directory/'new');old=unpack(BASELINE,directory/'old')
    baseline_hash=hashlib.sha256(BASELINE.read_bytes()).hexdigest()
    if BASELINE_SHA256 and baseline_hash!=BASELINE_SHA256:raise RuntimeError('0.2.0 baseline identity mismatch')
    classes=directory/'classes';classes.mkdir()
    subprocess.run(['javac','--release','21','-cp',str(new)+':'+str(runtime.ROOT/'.cache/logstash-jars')+'/*','-d',str(classes),str(runtime.ROOT/'tests/interop/JournalProbe.java')],check=True,timeout=60)
    def probe(role,jar,*arguments):
        relative=lambda path:'/work/'+path.relative_to(runtime.ROOT).as_posix()
        name='hec-journal-'+uuid.uuid4().hex
        return owned_probe(name,['--network','none','--entrypoint','/usr/share/logstash/jdk/bin/java','-v',str(runtime.ROOT)+':/work',
                runtime.P['logstash.'+role+'.image'],'-Xmx2g','-cp',relative(classes)+':'+relative(jar)+':/usr/share/logstash/logstash-core/lib/jars/*',
                'org.logstashplugins.hec.JournalProbe',*[relative(arg) if isinstance(arg,Path) else str(arg) for arg in arguments]])
    migration={'artifact':artifact,'validators':validators,'run_id':run_id,'baseline':{'file':BASELINE.name,'sha256':baseline_hash,'pinned_sha256':BASELINE_SHA256},'runs':[],'status':'fail'}
    scaling={'artifact':artifact,'validators':validators,'run_id':run_id,'runs':[],'status':'fail'}
    soak={'artifact':artifact,'validators':validators,'run_id':run_id,'runs':[],'status':'fail'}
    try:
        for role in ('minimum','latest'):
            path=directory/role;reference=directory/(role+'-reference')
            probe(role,old,'seed',path);before=assembly_state.read(path);original=(path/'state').read_bytes();shutil.copytree(path,reference)
            expected=directory/(role+'-expected.json');actual=directory/(role+'-actual.json')
            probe(role,old,'continue',reference,expected);probe(role,new,'continue',path,actual)
            assert native_json(expected)==native_json(actual),'migrated native events differ from uninterrupted 0.2.0'
            assert (path/'backup-v2').read_bytes()==original
            assert 'OLD_READER_REFUSED' in probe(role,old,'refuse',path)
            migrated=assembly_state.read(path)
            assert not migrated['pending'] and not migrated['outbox']
            assert migrated['receipts'].items()>=before['receipts'].items()
            migration['runs'].append({'role':role,'image':runtime.P['logstash.'+role+'.image'],'status':'pass',
                'pending_retained':bool(before['pending']),'outbox_retained':bool(before['outbox']),'receipts_retained':bool(before['receipts']),
                'backup_exact':True,'old_reader_refused':True,'continuation_matches':True,'retry_suppressed':True,'outputs':json.loads(actual.read_text())})
            print('PASS packaged migration',role,flush=True)
        migration['status']='pass'
        for lines in (500,1000,2000,4000,8000):
            result=json.loads(probe('latest',new,'scale',directory/('scale-'+str(lines)),lines).splitlines()[-1]);scaling['runs'].append(result)
            print('PASS packaged scaling',lines,flush=True)
        scaling['status']='pass'
        scaling['long_state_compaction']=json.loads(probe('latest',new,'compact-long',directory/'scale-8000').splitlines()[-1])
        seed=directory/'halt-seed';probe('latest',new,'seed',seed);expected_state=assembly_state.read(seed)
        scaling['process_halt_publication']=[]
        for boundary in ('snapshot-write','snapshot-sync','journal-write','journal-sync','generation-directory','pointer-write','pointer-sync','pointer-move','pointer-directory','publication-durable','cleanup'):
            target=directory/('halt-'+boundary);shutil.copytree(seed,target)
            try:probe('latest',new,'halt-publication',target,boundary)
            except subprocess.CalledProcessError as error:
                if error.returncode!=73:raise
            else:raise RuntimeError('Runtime.halt boundary not exercised')
            assert assembly_state.read(target)==expected_state,'process halt changed acknowledged state'
            # Reopen production store and continue seed; checks queued output/tail/receipts.
            probe('latest',new,'continue',target,directory/('halt-'+boundary+'.json'))
            scaling['process_halt_publication'].append({'boundary':boundary,'exit_code':73,'reopened':True,'scope':'Runtime.halt process crash; not power loss'})
        scaling['saturated_receipts']=json.loads(probe('latest',new,'receipts',directory/'saturated-receipts').splitlines()[-1])
        for role in ('minimum','latest'):
            result=json.loads(probe(role,new,'soak',directory/('soak-'+role)).splitlines()[-1]);result['role']=role;soak['runs'].append(result)
            assert result['memory_released'];print('PASS packaged soak',role,flush=True)
        soak['status']='pass'
        assert runtime.artifact_info()==artifact
    except BaseException as error:
        for report in (migration,scaling,soak):
            report['status']='fail';report['error']={'type':type(error).__name__,'message':str(error),'stdout':getattr(error,'stdout',None),'stderr':getattr(error,'stderr',None),'notes':getattr(error,'__notes__',[])}
        raise
    finally:
        for name,report in (('assembly-migration.json',migration),('journal-scaling.json',scaling),('assembly-soak.json',soak)):
            (runtime.EVIDENCE/name).write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':main()
