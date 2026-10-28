#!/usr/bin/env python3
"""V2 orchestration. Own resources, finite waits, fail closed, retain evidence."""
import argparse
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import runtime
from start_oracle import create_oracle
from senders import sender_ready

ROOT=runtime.ROOT

def run(script,*args):
    subprocess.run([sys.executable,str(ROOT/'tests/interop'/script),*args],check=True,timeout=7200)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage',choices=('all','runtime','senders','tcp'),default='all',
                        help='Run a targeted verification stage, or the full suite (default).')
    stage=parser.parse_args().stage
    owned=None
    try:
        if stage in ('all','runtime'):
            run('run_queue_probe.py')
            run('recovery.py')
            for role in ('minimum','latest'):
                output=runtime.docker('run','--rm','--network','none','-e','JAVA_HOME=/usr/share/logstash/jdk',
                    '-v',str(ROOT)+':/work:ro','--entrypoint','/usr/share/logstash/vendor/jruby/bin/jruby',
                    runtime.P[f'logstash.{role}.image'],'/work/tests/interop/version_guard.rb',runtime.P['logstash.'+role])
                print(output,flush=True)
            run('runtime.py')
        if stage=='runtime':return 0
        if stage=='tcp':
            # Real UF/HF classic TCP stage owns its Logstash receiver; no HEC oracle is required.
            run('tcp_senders.py')
            return 0
        existing=subprocess.run(['docker','inspect','hec-spec-oracle'],capture_output=True,timeout=30)
        if existing.returncode==0:raise RuntimeError('hec-spec-oracle already exists; refusing to take ownership')
        owned=create_oracle()
        direct=os.environ.get('HEC_STARTUP_MODE','direct')=='direct'
        if direct:
            sender_ready('hec-spec-oracle')
        # Cold amd64 Splunk provisioning under Desktop emulation can exceed ten
        # minutes. This is a fixture readiness budget, not an input IO deadline.
        deadline=time.monotonic()+900
        while time.monotonic()<deadline:
            status=json.loads(runtime.docker('inspect','hec-spec-oracle'))[0]['State']
            if not status['Running']:raise RuntimeError(runtime.docker('logs','hec-spec-oracle'))
            if direct:
                connection=http.client.HTTPConnection('127.0.0.1',18088,timeout=2)
                try:
                    connection.request('GET','/services/collector/health')
                    reply=connection.getresponse()
                    if reply.status==200 and json.loads(reply.read()).get('code')==17:break
                except (OSError,http.client.HTTPException,ValueError):pass
                finally:connection.close()
            elif status.get('Health',{}).get('Status')=='healthy':break
            time.sleep(2)
        else:
            diagnostic={'status':'startup-timeout','container':owned,
                'state':json.loads(runtime.docker('inspect',owned))[0]['State'],
                'logs':runtime.docker('logs',owned),'timeout_seconds':900}
            (ROOT/'tests/interop/evidence/oracle-startup-last-failure.json').write_text(json.dumps(diagnostic,indent=2)+'\n')
            raise RuntimeError('oracle startup deadline exceeded; see oracle-startup-last-failure.json')
        if not direct:
            runtime.docker('cp',str(ROOT/'tests/interop/oracle/configure.py'),'hec-spec-oracle:/tmp/configure-hec.py')
            runtime.docker('exec','--user','root','hec-spec-oracle','/opt/splunk/bin/python3','/tmp/configure-hec.py')
            runtime.docker('exec','--user','splunk','hec-spec-oracle','/opt/splunk/bin/splunk','restart',timeout=180)
        if stage=='all':run('capture_oracle.py')
        run('senders.py')
        run('tcp_senders.py')
        return 0
    finally:
        if owned:subprocess.run(['docker','rm','-f','-v',owned],capture_output=True,timeout=60)

if __name__=='__main__':sys.exit(main())
