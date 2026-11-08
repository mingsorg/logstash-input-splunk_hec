#!/usr/bin/env python3
"""Actual ENOSPC injection on owned 64KiB tmpfs, never the lab or host filesystem."""
import json
import socket
import sys
import assembly
import runtime
import assembly_state
import hashlib
from metadata_fields import finish_receiver, error_details

def main():
    report={'artifact':runtime.artifact_info(),'validators':runtime.validators_info(),'runs':[],'status':'fail'};rt=None
    try:
        for role in ('minimum','latest'):
            with socket.socket() as available:available.bind(('127.0.0.1',0));port=available.getsockname()[1]
            rules=[dict(assembly.RULES[0],flush_timeout_ms=60000)]
            rt=runtime.start_tcp_runtime(role,tls=True,queue='memory',tcp_port=port,s2s_line_breaker_rules=rules,
                docker_args=('--tmpfs','/run-hec/state/assembly:rw,size=65536,uid=1000,gid=1000,mode=0700'))
            assert assembly.post(rt,assembly.body('START retained'))[0]==200
            # The tmpfs is container-owned. Preserve the acknowledged prefix; failed appends
            # can leave an incomplete suffix and must be judged by authenticated replay.
            command=('exec',rt['name'],'sh','-c','cd /run-hec/state/assembly && tar cf - .')
            def capture(label):
                import subprocess,tarfile,io
                data=subprocess.run(['docker',*command],check=True,capture_output=True,timeout=30).stdout
                target=rt['directory']/label;target.mkdir()
                with tarfile.open(fileobj=io.BytesIO(data)) as archive:archive.extractall(target,filter='data')
                return assembly_state.read(target)
            before=capture('before-enospc')
            status,response=assembly.post(rt,assembly.body('x'*100000,14))
            assert status==503 and 'ackId' not in response,(status,response)
            after=capture('after-enospc')
            assert after==before,'ENOSPC changed accepted committed state'
            assert runtime.request(rt['port'],rt['context'],'health')[0]==503
            logs=runtime.docker('logs',rt['name'])
            assert 'assembly storage blocked' in logs,logs
            report['runs'].append({'role':role,'image':runtime.P['logstash.'+role+'.image'],'status':'pass','injection':'64KiB tmpfs; 100000-byte continuation exceeds actual filesystem capacity',
                                   'accepted_state_sha256':hashlib.sha256(json.dumps(before,sort_keys=True).encode()).hexdigest(),'response':response,'rejected_status':status,'health_status':503})
            if not finish_receiver(rt,report):raise RuntimeError('ENOSPC receiver cleanup failed')
            rt=None
        assert runtime.artifact_info()==report['artifact'];report['status']='pass'
    except Exception as error:report['error']=error_details(error)
    finally:
        if rt is not None:finish_receiver(rt,report,diagnostics=True)
        if report.get('cleanup_errors'):report['status']='fail'
        (runtime.EVIDENCE/'assembly-disk-full.json').write_text(json.dumps(report,indent=2)+'\n')
    if report['status']!='pass':print(report.get('error',{}),file=sys.stderr)
    return 0 if report['status']=='pass' else 1

if __name__=='__main__':sys.exit(main())
