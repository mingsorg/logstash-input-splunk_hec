#!/usr/bin/env python3
"""V2 orchestration. Own resources, finite waits, fail closed, retain evidence."""
import argparse
import http.client
import json
from pathlib import Path
import subprocess
import sys
import time
import runtime
from start_oracle import create_oracle

ROOT=runtime.ROOT

def run(script,*args):
    subprocess.run([sys.executable,str(ROOT/'tests/interop'/script),*args],check=True,timeout=3000)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage',choices=('all','runtime','senders'),default='all',
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
        existing=subprocess.run(['docker','inspect','hec-spec-oracle'],capture_output=True,timeout=30)
        if existing.returncode==0:raise RuntimeError('hec-spec-oracle already exists; refusing to take ownership')
        owned=create_oracle()
        # Cold amd64 Splunk provisioning under Desktop emulation can exceed ten
        # minutes. This is a fixture readiness budget, not an input IO deadline.
        deadline=time.monotonic()+900
        while time.monotonic()<deadline:
            status=json.loads(runtime.docker('inspect','hec-spec-oracle'))[0]['State']
            if not status['Running']:raise RuntimeError(runtime.docker('logs','hec-spec-oracle'))
            if status.get('Health',{}).get('Status')=='healthy':break
            time.sleep(2)
        else:
            diagnostic={'status':'startup-timeout','container':owned,
                'state':json.loads(runtime.docker('inspect',owned))[0]['State'],
                'logs':runtime.docker('logs',owned),'timeout_seconds':900}
            (ROOT/'tests/interop/evidence/oracle-startup-last-failure.json').write_text(json.dumps(diagnostic,indent=2)+'\n')
            raise RuntimeError('oracle startup deadline exceeded; see oracle-startup-last-failure.json')
        runtime.docker('cp',str(ROOT/'tests/interop/oracle/configure.py'),'hec-spec-oracle:/tmp/configure-hec.py')
        runtime.docker('exec','--user','root','hec-spec-oracle','/opt/splunk/bin/python3','/tmp/configure-hec.py')
        runtime.docker('exec','--user','splunk','hec-spec-oracle','/opt/splunk/bin/splunk','restart',timeout=180)
        if stage=='all':run('capture_oracle.py')
        run('senders.py')
        return 0
    finally:
        if owned:subprocess.run(['docker','rm','-f','-v',owned],capture_output=True,timeout=60)

if __name__=='__main__':sys.exit(main())
