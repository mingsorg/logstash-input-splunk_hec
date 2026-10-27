#!/usr/bin/env python3
"""Start an isolated pinned Splunk oracle; explicit license acceptance per spec."""
from pathlib import Path
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[2]
props = dict(s.split('=', 1) for s in (ROOT/'versions.properties').read_text().splitlines()
             if s and not s.startswith('#'))
def create_oracle():
    ownership='org.logstash.hec.oracle-run='+uuid.uuid4().hex
    cid=None
    try:
        cid=subprocess.check_output(['docker', 'create', '--name', 'hec-spec-oracle', '--platform', 'linux/amd64',
                '--label',ownership,
                '-p', '127.0.0.1:18088:8088', '-p', '127.0.0.1:18089:8089',
                '-e', 'SPLUNK_START_ARGS=--accept-license',
                '-e', 'SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com',
                '-e', 'SPLUNK_PASSWORD=HecOracle-Test-Only-487!',
                '-v', f'{ROOT}/tests/interop/oracle/inputs.conf:/tmp/hec-inputs.conf:ro',
                '-v', f'{ROOT}/tests/interop/oracle/props.conf:/tmp/hec-props.conf:ro',
                props['splunk.image']], text=True, timeout=120).strip()
        subprocess.run(['docker','start',cid],check=True,timeout=120)
        return cid
    except BaseException:
        # A create/start timeout can occur after the daemon has created the
        # container. Select by this run's unique label, never by a shared name.
        if cid:
            subprocess.run(['docker','rm','-f','-v',cid],capture_output=True,timeout=60)
        else:
            owned=subprocess.run(['docker','ps','-aq','--filter','label='+ownership],capture_output=True,text=True,timeout=30)
            if owned.returncode==0:
                for identity in owned.stdout.split():subprocess.run(['docker','rm','-f','-v',identity],capture_output=True,timeout=60)
        raise

if __name__=='__main__':create_oracle()
