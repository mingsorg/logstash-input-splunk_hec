#!/usr/bin/env python3
"""Real pinned UF/HF traffic: recording relay to plugin HTTPS and Splunk oracle.

Original request bodies are fixtures; the actual plugin response drives sender retries.
"""
import base64
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import threading
import time
import uuid
import zlib
from collections import Counter
import runtime
import os
import ssl
import urllib.parse
import urllib.request

ROOT=runtime.ROOT
EVIDENCE=ROOT/'tests/interop/evidence'
CAPTURES=ROOT/'tests/interop/fixtures/senders'

def sender_network():
    mode=os.environ.get('HEC_SENDER_NETWORK','auto')
    if mode=='auto':
        mode='bridge' if 'docker desktop' in runtime.docker('info','--format','{{.OperatingSystem}}').lower() else 'host'
    if mode not in ('host','bridge'):raise ValueError('HEC_SENDER_NETWORK must be auto, host or bridge')
    return (['--network','host'],'localhost') if mode=='host' else ([], 'host.docker.internal')

def sender_bootstrap_args(name):
    mode=os.environ.get('HEC_STARTUP_MODE','direct')
    return ['--init',*(['--no-healthcheck'] if mode=='direct' else []),'-e','HEC_FIXTURE_OWNED='+name,
        '-e','HEC_STARTUP_MODE='+mode,
        '-v',str(ROOT/'tests/interop/splunk_bootstrap.py')+':/tmp/splunk_bootstrap.py:ro']

def sender_ready(name, timeout=600):
    """A forwarder can emit traffic before its first-start CLI finishes."""
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        state=json.loads(runtime.docker('inspect',name,'--format','{{json .State}}'))
        if not state['Running']:raise RuntimeError('sender startup failed: '+runtime.docker('logs',name))
        if os.environ.get('HEC_STARTUP_MODE','direct')=='direct':
            probe=subprocess.run(['docker','exec',name,'test','-s','/tmp/hec-splunk-ready.json'],capture_output=True,timeout=30)
            if probe.returncode==0:return
        elif state.get('Health',{}).get('Status')=='healthy':return
        time.sleep(1)
    raise RuntimeError('sender startup deadline exceeded: '+runtime.docker('logs',name))

def main():
    CAPTURES.mkdir(parents=True,exist_ok=True)
    network_flags,receiver_host=sender_network()
    result,name,directory,port,context=runtime.run('latest',keep=True)
    records=[]
    versions={}
    injected={'count':0,'sha256':None}
    mutex=threading.Lock()
    class Relay(BaseHTTPRequestHandler):
        def handle_request(self):
            self.connection.settimeout(15)
            try:length=int(self.headers.get('Content-Length','0'))
            except ValueError:self.send_error(400);return
            if not 0<=length<=10*1024*1024:
                self.send_error(413 if length>0 else 400);return
            try:body=self.rfile.read(length)
            except (TimeoutError,ConnectionError):self.send_error(408);return
            if len(body)!=length:self.send_error(400);return
            headers={k:v for k,v in self.headers.items() if k.lower() not in ('host','content-length','connection')}
            entry={'method':self.command,'path':self.path,'user_agent':self.headers.get('User-Agent'),
                   'agent_build':self.headers.get('__splunk_app_version'),
                   'body_bytes':len(body),'body_sha256':hashlib.sha256(body).hexdigest(),
                   'channel':self.headers.get('X-Splunk-Request-Channel')}
            if body and '/s2s' in self.path and not self.path.endswith('health'):
                filename=entry['body_sha256']+'.bin'
                (CAPTURES/filename).write_bytes(body);entry['fixture']=filename
            responses={}
            for target in ('oracle','plugin'):
                # Outlast the receiver's 30-second IO deadline. A shorter relay
                # deadline can lose its response after queue acceptance and turn
                # ordinary host scheduling delays into an ambiguous retry.
                c=(http.client.HTTPConnection('127.0.0.1',18088,timeout=60) if target=='oracle' else
                   http.client.HTTPSConnection('localhost',port,context=context,timeout=60))
                try:
                    forwarded=dict(headers)
                    if target=='oracle':forwarded['Authorization']='Splunk '+runtime.TOKEN
                    forwarded_body=body
                    corrupt=False
                    if target=='plugin' and body and '/s2s' in self.path:
                        with mutex:
                            if injected['sha256'] is None:injected['sha256']=entry['body_sha256']
                            if injected['count']<2 and injected['sha256']==entry['body_sha256']:
                                injected['count']+=1;corrupt=True
                    if corrupt:
                        expanded=zlib.decompressobj().decompress(body[1:])
                        forwarded_body=b'\xf9'+zlib.compress(expanded+b'\xfb')
                        entry['injected_invalid_opcode']=True
                    c.request(self.command,self.path,forwarded_body,forwarded)
                    response=c.getresponse();responses[target]=(response.status,response.read())
                    entry[target]={'status':responses[target][0],'body':responses[target][1].decode()}
                except Exception as e:
                    responses[target]=(503,b'{"text":"relay failure","code":9}');entry[target]={'error':str(e)}
                finally:c.close()
            with mutex: records.append(entry)
            status,payload=responses['plugin']
            try:
                self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
            except (BrokenPipeError,ConnectionResetError):
                entry['sender_disconnected']=True
        do_POST=do_GET=handle_request
        def log_message(self,*args):pass
    server=None
    try:
        server=ThreadingHTTPServer(('0.0.0.0',18090),Relay)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    except BaseException:
        if server is not None:server.server_close()
        subprocess.run(['docker','rm','-f','-v',name],capture_output=True,timeout=60)
        raise
    senders=[]
    try:
        for role,image,home in [('uf',runtime.P['uf.image'],'/opt/splunkforwarder'),('hf',runtime.P['splunk.image'],'/opt/splunk')]:
            before=len(records)
            sender='hec-sender-'+role+'-'+uuid.uuid4().hex[:8];senders.append(sender)
            runtime.docker('run','-d','--name',sender,'--platform','linux/amd64','--user','root',
                *sender_bootstrap_args(sender),
                *network_flags,'-e','HEC_RECEIVER_URI=http://'+receiver_host+':18090',
                '-e','SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com',
                '-v',str(ROOT/'tests/interop/sender_setup.py')+':/tmp/hec-sender-setup.py:ro',
                '--entrypoint','/usr/bin/python3',image,'/tmp/hec-sender-setup.py')
            deadline=time.monotonic()+600
            while time.monotonic()<deadline:
                with mutex:
                    product='splunkforwarder-' if role=='uf' else 'splunk-'
                    data=[r for r in records[before:] if r.get('fixture') and (r.get('agent_build') or '').startswith(product)]
                # The first requests can be deliberately rejected. Do not stop
                # a real forwarder until an unmodified batch has been accepted.
                if any(r['plugin'].get('status')==200 and not r.get('injected_invalid_opcode') for r in data):break
                if runtime.docker('inspect',sender,'--format','{{.State.Running}}')!='true':
                    raise RuntimeError(runtime.docker('inspect',sender,'--format','{{json .State}}')+'\n'+runtime.docker('logs',sender))
                time.sleep(1)
            else:raise RuntimeError(role+' did not send data: '+json.dumps(records)+'\n'+runtime.docker('logs',sender))
            sender_ready(sender)
            time.sleep(5)
            versions[role]={'image':image,'architecture':'linux/amd64',
                'host':runtime.docker('inspect',sender,'--format','{{.Config.Hostname}}'),
                'version':runtime.docker('exec','--user','splunk',sender,home+'/bin/splunk','version')}
            for r in data:
                if r['plugin'].get('status')!=200:print('SENDER REJECTION',json.dumps(r),flush=True)
            runtime.docker('rm','-f','-v',sender)
            senders.remove(sender)
            time.sleep(2)
        time.sleep(10)
        events=runtime.read_events(directory/'events.ndjson')
        observed=[e for e in events if e.get('source','').startswith('/tmp/hec-source.')]
        assert len(observed)==12,('expected five text + one structured event from each sender',len(observed))
        assert Counter(e['event'] for e in observed if e['source'].endswith('.log'))==Counter({'alpha':2,'  indented remains separate':2,'重复':2,'repeat':4})
        repeated=[e['verification_metadata']['splunk_hec']['id'] for e in observed if e['event']=='repeat']
        assert len(set(repeated))==4,'distinct repeated source occurrences collapsed'
        rejected=[r for r in records if r.get('injected_invalid_opcode')]
        assert all('error' not in r[target] for r in records for target in ('oracle','plugin')),('relay failed',records)
        assert len(rejected)==2 and all(r['plugin']['status']==400 and json.loads(r['plugin']['body'])['code']==6 for r in rejected)
        assert len({r['body_sha256'] for r in rejected})==1,'expected identical-batch sender retry after rejection'
        assert any(r['body_sha256']==rejected[0]['body_sha256'] and r['plugin']['status']==200 for r in records if not r.get('injected_invalid_opcode'))
        for r in records:
            if r.get('fixture') and not r.get('injected_invalid_opcode'):
                assert r['plugin']['status'] in (200,503),r
                if r['plugin']['status']==503:assert json.loads(r['plugin']['body'])=={'text':'Server is busy','code':9}
        initial=list(observed)
        host_filter=' OR '.join('host="'+v['host']+'"' for v in versions.values())
        query='search index=main earliest=0 source="/tmp/hec-source.*" ('+host_filter+')'
        data=urllib.parse.urlencode({'search':query,'output_mode':'json'}).encode()
        req=urllib.request.Request('https://127.0.0.1:18089/services/search/jobs/export',data=data,
            headers={'Authorization':'Basic '+base64.b64encode(b'admin:HecOracle-Test-Only-487!').decode()})
        with urllib.request.urlopen(req,context=ssl._create_unverified_context(),timeout=60) as response:
            indexed=[json.loads(line)['result'] for line in response if b'"result"' in line]
        indexed_values=Counter(e['_raw'] for e in indexed)
        source_values=Counter(e['event'] for e in initial)
        assert all(indexed_values[value]>=count for value,count in source_values.items()),('oracle source values missing',indexed_values,source_values)
        # Real new HTTP connections replay the exact accepted bodies. The input must
        # retain duplicates, while the versioned IDs remain stable for an idempotent output.
        replayed=set()
        for record in records:
            if record.get('fixture') and record['plugin'].get('status')==200 and record['fixture'] not in replayed:
                replayed.add(record['fixture'])
                connection=http.client.HTTPSConnection('localhost',port,context=context,timeout=15)
                try:
                    connection.request('POST',record['path'],(CAPTURES/record['fixture']).read_bytes(),
                        {'Authorization':'Splunk 55555555-5555-4555-8555-555555555555'})
                    response=connection.getresponse();payload=response.read()
                    assert response.status==200,(response.status,payload)
                finally:connection.close()
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            events=runtime.read_events(directory/'events.ndjson')
            observed=[e for e in events if e.get('source','').startswith('/tmp/hec-source.')]
            if len(observed)>=24:break
            time.sleep(.2)
        original_ids=Counter(e['verification_metadata']['splunk_hec']['id'] for e in initial)
        assert Counter(e['verification_metadata']['splunk_hec']['id'] for e in observed)==Counter({k:v*2 for k,v in original_ids.items()}),'real reconnect/replay ID instability or source loss'
        direct_tls=[]
        for role,image in [('uf',runtime.P['uf.image']),('hf',runtime.P['splunk.image'])]:
            sender='hec-sender-tls-'+role+'-'+uuid.uuid4().hex[:8];senders.append(sender)
            before=len(observed)
            runtime.docker('run','-d','--name',sender,'--platform','linux/amd64','--user','root',
                *sender_bootstrap_args(sender),
                *network_flags,
                '-e','SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com',
                '-e','HEC_RECEIVER_URI=https://'+receiver_host+':'+str(port),
                '-v',str(ROOT/'tests/interop/sender_setup.py')+':/tmp/hec-sender-setup.py:ro',
                '-v',str(directory/'state/identity/server.crt')+':/tmp/hec-server.crt:ro',
                '--entrypoint','/usr/bin/python3',image,'/tmp/hec-sender-setup.py')
            deadline=time.monotonic()+600
            while time.monotonic()<deadline:
                events=runtime.read_events(directory/'events.ndjson')
                observed=[e for e in events if e.get('source','').startswith('/tmp/hec-source.')]
                if len(observed)>=before+6:break
                if runtime.docker('inspect',sender,'--format','{{.State.Running}}')!='true':raise RuntimeError(runtime.docker('logs',sender))
                time.sleep(1)
            else:raise RuntimeError(role+' verified direct HTTPS sender timed out: '+runtime.docker('logs',sender))
            sender_ready(sender)
            assert len(observed)==before+6,(role,'unexpected direct TLS source count',len(observed))
            direct_tls.append({'role':role,'verified_trust_and_hostname':True,'source_event_count':6,'image':image})
            runtime.docker('rm','-f','-v',sender);senders.remove(sender)
        (EVIDENCE/'senders.json').write_text(json.dumps({'traffic':records,'events':observed,
            'artifact':result['artifact'],'startup_mode':os.environ.get('HEC_STARTUP_MODE','direct'),
            'versions':versions,'status':'pass','direct_tls':direct_tls,
            'oracle_indexed_events':indexed,'initial_source_event_count':len(initial),
            'identical_body_replay_source_event_count':12,'reconnect_ids_stable':True,
            'resource_rejections':sum(r.get('plugin',{}).get('status')==503 for r in records),
            'scope':'live UF/HF traffic, deliberate invalid-batch retries, identical-body replay and direct verified HTTPS'},indent=2)+'\n')
        print('PASS',len(records),'requests;',len(observed),'source events',flush=True)
    finally:
        (EVIDENCE/'sender-traffic-last-run.json').write_text(json.dumps(records,indent=2)+'\n')
        (EVIDENCE/'sender-versions-last-run.json').write_text(json.dumps(versions,indent=2)+'\n')
        if (directory/'events.ndjson').exists():
            source_events=[event for event in runtime.read_events(directory/'events.ndjson')
                           if event.get('source','').startswith('/tmp/hec-source.')]
            (EVIDENCE/'sender-source-events-last-run.json').write_text(json.dumps(source_events,indent=2)+'\n')
        server.shutdown();server.server_close();thread.join(5)
        for container in [*senders,name]:subprocess.run(['docker','rm','-f','-v',container],capture_output=True,timeout=60)

if __name__=='__main__':main()
