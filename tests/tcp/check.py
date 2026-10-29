#!/usr/bin/env python3
"""Gate for the classic S2S TCP listener claim.

Passes only when retained evidence from REAL latest UF/HF senders connecting
directly to the packaged plugin covers the full declared matrix AND names the
exact gem currently in this directory. Missing, failed, partial or stale
evidence exits 2; it is never reported as a skipped pass.
"""
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
EVIDENCE=ROOT/'tests/interop/evidence/tcp-senders.json'
CAPTURE=ROOT/'tests/tcp/evidence'

def blocked(reason):
    print(json.dumps({'status':'blocked','tcp_claim_qualified':False,'reason':reason}))
    sys.exit(2)

def main():
    if not EVIDENCE.exists():blocked('tests/interop/evidence/tcp-senders.json is absent; run the real UF/HF TCP stage')
    report=json.loads(EVIDENCE.read_text())
    if report.get('status')!='pass':blocked('the retained real-sender TCP run did not pass')
    gems=sorted(ROOT.glob('logstash-input-splunk_hec-*-java.gem'))
    if not gems:blocked('build the gem so its digest can be compared with the evidence')
    digest=hashlib.sha256(gems[-1].read_bytes()).hexdigest()
    if report.get('artifact',{}).get('sha256')!=digest:
        blocked('stale evidence: it names a different gem digest than '+gems[-1].name)
    expected={(role,compressed,ack,tls) for role in ('uf','hf') for compressed in (False,True)
              for ack in (False,True) for tls in (False,True)}
    observed={(row['role'],row['compressed'],row['useACK'],row['tls_verified_hostname_and_trust'])
              for row in report.get('matrix',[]) if row.get('source_event_count')==6}
    if observed!=expected:blocked('matrix is incomplete: missing '+repr(sorted(expected-observed)))
    restart=report.get('restart',{}).get('restart',{})
    if not (restart.get('receiver_killed_with_sigkill') and restart.get('all_delivered_after_restart')):
        blocked('receiver kill/restart delivery evidence is absent')
    if set(report.get('hec_metadata_modes',{}))!={'id_only','none'}:blocked('real-sender hec_metadata id_only/none evidence is absent')
    if len(report.get('minimum_logstash',{}).get('runs',[]))<2:blocked('minimum Logstash TCP runs are absent')
    for name in ('decoded-capture.json','decoded-capture-compressed.json'):
        if not (CAPTURE/name).exists():blocked(name+' (oracle wire analysis) is absent')
    print(json.dumps({'status':'pass','tcp_claim_qualified':True,'artifact_sha256':digest,
        'sender_runs':len(report['matrix']),'scope':report.get('scope')}))

if __name__=='__main__':main()
