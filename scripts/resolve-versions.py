#!/usr/bin/env python3
"""Inspect immutable pins; GA discovery is opt-in and produces a review candidate.

Never resolve `latest` during builds. Refresh does not edit the approved lock.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
P=dict(s.split('=',1) for s in (ROOT/'versions.properties').read_text().splitlines() if s and not s.startswith('#'))

def get(url):
    with urllib.request.urlopen(url,timeout=60) as r:return json.load(r)

def inspect(image):
    output=subprocess.check_output(['docker','buildx','imagetools','inspect',image],text=True,timeout=120)
    digest=re.search(r'^Digest:\s+(sha256:[0-9a-f]{64})$',output,re.M)
    if not digest:raise ValueError('registry did not return an immutable digest')
    return {'image':image,'digest':digest[1],'platforms':re.findall(r'Platform:\s+(\S+)',output),'registry_observation':output}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--refresh-ga',action='store_true',help='discover numeric GA tags and write an unapproved candidate; never used by builds')
    args=parser.parse_args()
    records={key:inspect(value) for key,value in P.items() if key.endswith('.image')}
    if args.refresh_ga:
        releases=get('https://api.github.com/repos/elastic/logstash/releases?per_page=100')
        ga=[r['tag_name'] for r in releases if not r['prerelease'] and not r['draft'] and re.fullmatch(r'v\d+\.\d+\.\d+',r['tag_name'])]
        if not ga:raise ValueError('no verified GA Logstash release found')
        latest=max(ga,key=lambda s:tuple(map(int,s[1:].split('.'))))
        records['candidate.logstash']=inspect('docker.elastic.co/logstash/logstash:'+latest[1:])
        for repository in ('splunk','universalforwarder'):
            tags=get('https://hub.docker.com/v2/repositories/splunk/'+repository+'/tags?page_size=100')['results']
            stable=[t['name'] for t in tags if re.fullmatch(r'\d+\.\d+\.\d+(\.\d+)?',t['name'])]
            if not stable:raise ValueError('no numeric GA Splunk tag found')
            tag=max(stable,key=lambda s:tuple(map(int,s.split('.'))))
            records['candidate.'+repository]=inspect('splunk/'+repository+':'+tag)
    report={'approved_lock_sha256':hashlib.sha256((ROOT/'versions.properties').read_bytes()).hexdigest(),
            'refresh_requested':args.refresh_ga,'images':records}
    destination=ROOT/('versions-candidate.json' if args.refresh_ga else 'tests/interop/evidence/images.json')
    destination.write_text(json.dumps(report,indent=2)+'\n')
    print(destination)

if __name__=='__main__':main()
