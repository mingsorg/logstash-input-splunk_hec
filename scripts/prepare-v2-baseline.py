#!/usr/bin/env python3
"""Explicitly prepare the checksum-pinned release fixture; never overwrite a baseline."""
import hashlib
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
NAME='logstash-input-splunk_hec-0.2.0-java.gem'
SHA256='3dbc0a7162c10d3c666562b274200cca487f2d96176b683bb8a6f598b06cdc11'

def main():
    destination=ROOT/NAME
    if destination.exists():
        if hashlib.sha256(destination.read_bytes()).hexdigest()!=SHA256:raise SystemExit('Existing baseline digest differs; refusing to overwrite it')
        print('Pinned baseline already prepared');return
    if sys.argv[1:]!=['--download']:raise SystemExit('Missing baseline. Run python3 scripts/prepare-v2-baseline.py --download after reviewing docs/installation.md baseline preparation.')
    print('Downloading the v0.2.0 release fixture from GitHub; requires GitHub/network access.',flush=True)
    temporary=ROOT/'build/baseline-download';temporary.mkdir(parents=True,exist_ok=True)
    subprocess.run(['gh','release','download','v0.2.0','--repo','mingsorg/logstash-input-splunk_hec','--pattern',NAME,'--dir',str(temporary)],check=True)
    payload=(temporary/NAME).read_bytes()
    if hashlib.sha256(payload).hexdigest()!=SHA256:raise SystemExit('Downloaded release digest mismatch; baseline not installed')
    with destination.open('xb') as output:output.write(payload)
    print('Pinned baseline prepared')

if __name__=='__main__':main()
