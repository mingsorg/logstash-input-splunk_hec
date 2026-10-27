#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid
import runtime

def main():
    results=[]
    for role in sys.argv[1:] or ['minimum','latest']:
        directory=runtime.ROOT/'build/interop'/('recovery-'+uuid.uuid4().hex)
        directory.mkdir(parents=True);directory.chmod(0o777)
        for mode in ['write','read']:
            name='hec-pq-'+uuid.uuid4().hex[:10]
            try:
                run=subprocess.run(['docker','run','--rm','--name',name,'--network','none',
                    '-e','JAVA_HOME=/usr/share/logstash/jdk','-v',str(runtime.ROOT)+':/work:ro',
                    '-v',str(directory)+':/pq','--entrypoint','/usr/share/logstash/vendor/jruby/bin/jruby',
                    runtime.P[f'logstash.{role}.image'],'/work/tests/interop/recovery_probe.rb',mode],
                    capture_output=True,text=True,timeout=120)
                result={'role':role,'mode':mode,'image':runtime.P[f'logstash.{role}.image'],
                        'exit_code':run.returncode,'stdout':run.stdout,'stderr':run.stderr}
                results.append(result);print(json.dumps(result,indent=2),flush=True)
                if run.returncode:break
            finally:subprocess.run(['docker','rm','-f','-v',name],capture_output=True,timeout=60)
    (runtime.ROOT/'tests/interop/evidence/pq-recovery.json').write_text(json.dumps(results,indent=2)+'\n')
    return int(any(r['exit_code'] for r in results))

if __name__=='__main__':sys.exit(main())
