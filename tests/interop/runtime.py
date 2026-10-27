#!/usr/bin/env python3
"""Packaged-gem install + verified HTTPS on minimum/latest Java 21 runtimes.

All waits are finite. Docker resources owned by this run are removed in finally.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import time
import uuid
import importlib.util

ROOT = Path(__file__).resolve().parents[2]
P = dict(line.split('=', 1) for line in (ROOT/'versions.properties').read_text().splitlines()
         if line and not line.startswith('#'))
TOKEN = '11111111-1111-4111-8111-111111111111'
CHANNEL = '12345678-1234-4234-8234-123456789abc'

def docker(*args, **kw):
    return subprocess.run(['docker', *args], check=True, text=True, capture_output=True, timeout=kw.pop('timeout', 120), **kw).stdout.strip()

def request(port, context, path, body=None):
    c = http.client.HTTPSConnection('localhost', port, context=context, timeout=15)
    try:
        headers={'Authorization':'Splunk '+TOKEN, 'X-Splunk-Request-Channel':CHANNEL}
        c.request('GET' if body is None else 'POST', '/services/collector/'+path,
                  None if body is None else json.dumps(body), headers)
        r=c.getresponse()
        return r.status, json.loads(r.read())
    finally:
        c.close()

def ready(name,directory):
    port=int(docker('port',name,'8088/tcp').split(':')[-1])
    deadline=time.monotonic()+600
    while time.monotonic()<deadline:
        try:
            context=ssl.create_default_context(cafile=str(directory/'state/identity/server.crt'))
            if request(port,context,'health')[0]==200:return port,context
        except (OSError,ValueError,ssl.SSLError):pass
        if docker('inspect',name,'--format','{{.State.Running}}')!='true':
            raise RuntimeError('runtime exited: '+docker('inspect',name,'--format','{{json .State}}')+'\n'+docker('logs',name))
        time.sleep(1)
    raise RuntimeError('runtime readiness timeout: '+docker('logs',name)+'\n'+docker('top',name))

def run(role, queue='persisted', keep=False):
    success=False
    name='hec-runtime-'+uuid.uuid4().hex[:10]
    directory=ROOT/'build/interop'/name
    config=directory/'config'
    config.mkdir(parents=True)
    directory.chmod(0o777)
    (config/'logstash.yml').write_text('''pipeline.workers: 1
pipeline.batch.size: 1
api.enabled: false
xpack.monitoring.enabled: false
path.data: /run-hec/data
path.logs: /run-hec/logs
queue.type: '''+queue+'''
queue.max_bytes: 16mb
queue.page_capacity: 1mb
queue.checkpoint.writes: 1
queue.checkpoint.acks: 1
''')
    (config/'pipelines.yml').write_text('- pipeline.id: main\n  path.config: /run-hec/config/pipeline.conf\n')
    (config/'pipeline.conf').write_text('''input { splunk_hec {
  host => "0.0.0.0" port => 8088 state_directory => "/run-hec/state"
  ssl_self_signed_sans => "dns:localhost,dns:host.docker.internal,ip:127.0.0.1,ip:::1"
  tokens_json => '[{"token":"'''+TOKEN+'''","useACK":true},{"token":"55555555-5555-4555-8555-555555555555","useACK":false}]'
} }
filter { ruby { code => 'while File.exist?("/run-hec/stall"); sleep 0.1; end; event.set("verification_metadata", event.get("@metadata"))' } }
output { file { path => "/run-hec/events.ndjson" codec => json_lines flush_interval => 0 } }
''')
    try:
        docker('run','-d','--name',name,'-p','127.0.0.1::8088',
               '-e','JAVA_HOME=/usr/share/logstash/jdk','-v',str(ROOT)+':/work:ro',
               '-v',str(directory)+':/run-hec','--entrypoint','/usr/share/logstash/vendor/jruby/bin/jruby',
               P[f'logstash.{role}.image'],'/work/tests/interop/install_and_run.rb')
        port,context=ready(name,directory)
        payload={'event':{'message':'native', 'a.b':[1,2.5,True,None], 'large':9223372036854775807},
                 'time':'1700000000.123456789','host':'original','source':'native-test','fields':{'literal.name':['a','b']}}
        status,response=request(port,context,'event',payload)
        assert status==200,(status,response)
        ack=response['ackId']
        assert request(port,context,'ack',{'acks':[ack,ack]})==(200,{'acks':{str(ack):True}})
        assert request(port,context,'ack',{'acks':[ack]})==(200,{'acks':{str(ack):False}})
        output=directory/'events.ndjson'
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            if output.exists() and output.stat().st_size: break
            time.sleep(.2)
        event=json.loads(output.read_text().splitlines()[0])
        assert event['event']==payload['event'],event
        assert event['time']==payload['time'] and event['@timestamp']=='2023-11-14T22:13:20.123456789Z',event
        assert 'message' not in event and event['host']=='original' and event['fields']==payload['fields'],event
        assert request(port,context,'event',{'event':0.1})[0]==200
        spec=importlib.util.spec_from_file_location('hec_http_checks',ROOT/'tests/http/check.py')
        http_checks=importlib.util.module_from_spec(spec);spec.loader.exec_module(http_checks)
        black_box=http_checks.check('https://localhost:'+str(port),directory/'state/identity/server.crt',TOKEN)
        restart=None
        if role=='latest' and queue=='persisted' and not keep:
            certificate=(directory/'state/identity/server.crt').read_bytes()
            gate=directory/'stall';gate.write_text('hold output before deliberate process crash')
            status,response=request(port,context,'event',{'event':'recover-after-crash','time':'1700000000.123456789'})
            assert status==200,(status,response)
            outstanding=response['ackId']
            time.sleep(1)
            assert 'recover-after-crash' not in output.read_text(),'output was not held'
            docker('kill','--signal','KILL',name)
            gate.unlink()
            docker('start',name)
            port,context=ready(name,directory)
            assert (directory/'state/identity/server.crt').read_bytes()==certificate,'TLS identity changed at restart'
            assert request(port,context,'ack',{'acks':[outstanding]})==(200,{'acks':{str(outstanding):False}})
            status,new=request(port,context,'event',{'event':'new-after-restart'})
            assert status==200 and new['ackId']>outstanding
            deadline=time.monotonic()+30
            while time.monotonic()<deadline and 'recover-after-crash' not in output.read_text():time.sleep(.2)
            recovered=[json.loads(line) for line in output.read_text().splitlines() if 'recover-after-crash' in line]
            assert len(recovered)==1 and recovered[0]['@timestamp']=='2023-11-14T22:13:20.123456789Z',recovered
            restart={'pq_unacked_event_recovered':True,'old_ack_unknown':True,'old_ack_id':outstanding,
                     'new_ack_id':new['ackId'],'certificate_reused':True}
        result=dict(role=role,queue=queue,image=P[f'logstash.{role}.image'],
                    installed=True,verified_https=True,ack_consumed=True,event=event,
                    black_box_http=black_box,
                    restart=restart,
                    java=docker('exec',name,'/usr/share/logstash/jdk/bin/java','-version'),
                    logs=docker('logs',name))
        if keep:
            success=True
            return result, name, directory, port, context
        return result
    finally:
        if not keep or not success: subprocess.run(['docker','rm','-f','-v',name],capture_output=True,timeout=60)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('roles',nargs='*',help='minimum and/or latest; both by default')
    parser.add_argument('--queue',choices=('memory','persisted'),action='append',help='queue types to verify; both by default')
    options=parser.parse_args()
    roles=options.roles or ['minimum','latest']
    if any(role not in ('minimum','latest') for role in roles):parser.error('roles must be minimum or latest')
    results=[]
    for role in roles:
        for queue in options.queue or ['memory','persisted']:
            try:
                result=run(role,queue)
                results.append(result)
                print(role,queue,'PASS',flush=True)
            except Exception as e:
                results.append(dict(role=role,queue=queue,error=str(e)))
                print(role,queue,'FAIL',str(e),flush=True)
    out=ROOT/'tests/interop/evidence/runtime.json'
    existing=json.loads(out.read_text()) if out.exists() else []
    replaced={(row['role'],row['queue']) for row in results}
    combined=[row for row in existing if (row.get('role'),row.get('queue')) not in replaced]+results
    out.write_text(json.dumps(combined,indent=2)+'\n')
    return int(any('error' in r for r in results))

if __name__=='__main__': sys.exit(main())
