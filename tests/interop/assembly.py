#!/usr/bin/env python3
"""Release-scoped, owned real UF/HF multiline and packaged crash-recovery qualification."""
from collections import Counter
import http.client
import json
import socket
import signal
import sys
import time
import uuid
import zlib

import runtime
import assembly_state
from senders import sender_bootstrap_args, sender_network, sender_ready
from metadata_fields import cleanup_sender, finish_receiver, error_details

RULES=[{'match':'exact','sourcetype':'hec_assembly_selected','event_start_pattern':'^START','flush_timeout_ms':3000},
       {'match':'glob','sourcetype':'hec_assembly_*','event_start_pattern':'^NEVER','flush_timeout_ms':3000}]
# A deliberately unmatched fallback needs no catch-all glob: select an unrelated prefix instead.
RULES[1]['sourcetype']='other:*'
MAPPING={'_path':'path','crcSalt':'salt'}

def wait_for(predicate, seconds=300):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        result=predicate()
        if result:return result
        time.sleep(.25)
    raise TimeoutError('assembly qualification observation deadline')

def selected_events(rt,host):
    return [event for event in runtime.read_events(rt['directory']/'events.ndjson') if event.get('host')==host
            and (event.get('source','').startswith('/tmp/hec-assembly-') or event.get('source')=='/tmp/hec-source.json')]

def check(events,role,mode,transport):
    fallback=[event for event in events if event['source'].endswith('fallback.log')]
    assert Counter(e['event'] for e in fallback)==Counter(['fallback','  separate','repeat']),fallback
    structured=[e for e in events if e['source'].endswith('.json')]
    assert len(structured)==1 and structured[0]['fields']['a.b{}']==['first','second'],structured
    selected=[event for event in events if event['sourcetype']=='hec_assembly_selected']
    assert len(selected)==4,selected
    for name in ('a','b'):
        source=[e for e in selected if e['source'].endswith('-'+name+'.log')]
        assert len(source)==2,source
        # UF keeps the internal blank line. The HTTP sender strips the final record
        # delimiter; cooked TCP keeps it. HF's native structured breaker strips both
        # event-ending delimiters, as observed in the retained native captures.
        first='START '+name+' one\n  trace '+name
        second='START '+name+' two\n  end '+name
        expected=[first+'\n\n',second+('\n' if transport=='tcp' else '')] if role=='uf' else [first,second]
        assert Counter(e['event'] for e in source)==Counter(expected),source
        for event in source:
            assert event['index']=='main' and 'message' not in event and event['s2s_metadata']['path']==event['source'],event
            metadata=event.get('verification_metadata',{}).get('splunk_hec',{})
            if mode=='none':assert not metadata,event
            else:
                assert metadata['id'].startswith('s2s-assembled-v1:' if role=='uf' else 's2s-v1:'),event
                if mode=='id_only':assert set(metadata)=={'id'},metadata
    return {'selected':selected,'fallback':fallback,'structured':structured}

def real_sender(rt,role,transport,mode,flags,host,row):
    image=runtime.P['uf.image' if role=='uf' else 'splunk.image']
    name='hec-assembly-'+role+'-'+uuid.uuid4().hex[:10]
    ownership='org.logstash.hec.assembly-run='+uuid.uuid4().hex
    identity=None
    try:
        arguments=['create','--name',name,'--label',ownership,'--platform','linux/amd64','--user','root',
                   *sender_bootstrap_args(name),*flags,'-e','HEC_ASSEMBLY_FIXTURE=true',
                   '-e','SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com',
                   '-v',str(runtime.ROOT/'tests/interop/sender_setup.py')+':/tmp/hec-sender-setup.py:ro',
                   '-v',str(rt['directory']/'state/identity/server.crt')+':/tmp/hec-server.crt:ro']
        if transport=='http':arguments+=['-e','HEC_RECEIVER_URI=https://'+host+':'+str(rt['port'])]
        else:arguments+=['-e','HEC_TRANSPORT=tcp','-e','HEC_TCP_RECEIVER='+host+':'+str(rt['tcp_port']),
                         '-e','HEC_TCP_COMPRESSED=true','-e','HEC_TCP_ACK=true','-e','HEC_TCP_TLS=true']
        identity=runtime.docker(*arguments,'--entrypoint','/usr/bin/python3',image,'/tmp/hec-sender-setup.py')
        runtime.docker('start',identity);sender_host=runtime.docker('inspect',identity,'--format','{{.Config.Hostname}}')
        events=wait_for(lambda: (values if len(values:=selected_events(rt,sender_host))>=8 else None),600)
        sender_ready(identity);time.sleep(4);events=selected_events(rt,sender_host)
        checked=check(events,role,mode,transport)
        home='/opt/splunkforwarder' if role=='uf' else '/opt/splunk'
        row.update(status='pass',sender_image=image,sender_version=runtime.docker('exec','--user','splunk',identity,home+'/bin/splunk','version'),
                   verified_tls=True,events=checked)
    except Exception as failure:
        row['error']=error_details(failure)
        if identity:
            try:row['sender_logs']=runtime.docker('logs',identity)
            except Exception as diagnostic_failure:
                row.setdefault('diagnostic_errors',[]).append(error_details(diagnostic_failure))
        raise
    finally:
        if not cleanup_sender(identity,ownership,row):row['status']='fail';raise RuntimeError('assembly sender cleanup failed')

def varint(value):
    out=bytearray()
    while value>127:out.append((value&127)|128);value>>=7
    out.append(value);return bytes(out)

def string(value,nullable=False):
    value=value.encode();return varint(len(value)+(1 if nullable else 0))+value

def body(text,offset=0,suffix=b'',seconds=1700000000,source='assembly-crash'):
    meta=b'\xfe\x01'+b''.join(string(x,True) for x in ('source::'+source,'host::assembly-probe','sourcetype::hec_assembly_selected','channel'))+b'\x00'
    event=b'\xfc\x01\x0a'+b''.join(varint(x) for x in (7,offset,1,seconds))+b'\x00'+string(text)
    return b'\xf9'+zlib.compress(meta+event+suffix)

def post(rt,payload):
    connection=http.client.HTTPSConnection('localhost',rt['port'],context=rt['context'],timeout=20)
    try:
        connection.request('POST','/services/collector/s2s',payload,{'Authorization':'Splunk '+runtime.TOKEN,'X-Splunk-Request-Channel':runtime.CHANNEL})
        response=connection.getresponse();return response.status,json.loads(response.read())
    finally:connection.close()

def crash_probe(rt):
    status,response=post(rt,body('START retained'))
    assert status==200 and 'ackId' in response,(status,response)
    ack=response['ackId']
    assert runtime.request(rt['port'],rt['context'],'ack',{'acks':[ack]})==(200,{'acks':{str(ack):True}})
    snapshot=rt['directory']/'state/assembly'
    before=assembly_state.retained_bytes(snapshot)
    assert any(pending['text']=='START retained' for pending in assembly_state.read(snapshot)['pending'].values())
    assert not [e for e in runtime.read_events(rt['directory']/'events.ndjson') if e.get('source')=='assembly-crash']
    assert post(rt,body('bad',14,b'\xfb'))[0]==400
    assert assembly_state.retained_bytes(snapshot)==before,'invalid batch changed accepted state'
    runtime.docker('kill','--signal','KILL',rt['name']);runtime.docker('start',rt['name'])
    rt['port'],rt['context']=runtime.ready(rt['name'],rt['directory'])
    assert runtime.request(rt['port'],rt['context'],'ack',{'acks':[ack]})==(200,{'acks':{str(ack):False}})
    # The 3s idle deadline may have elapsed during startup, so the durable first tail
    # must appear intact; later continuations cannot mutate its finalized value.
    events=wait_for(lambda: [e for e in runtime.read_events(rt['directory']/'events.ndjson') if e.get('source')=='assembly-crash'])
    assert len(events)==1 and events[0]['event']=='START retained',events
    assert post(rt,body('START retained'))[0]==200
    time.sleep(1)
    assert len([e for e in runtime.read_events(rt['directory']/'events.ndjson') if e.get('source')=='assembly-crash'])==1
    return {'sigkill_after_durable_success':True,'ack_polled_before_kill':True,'pending_snapshot_before_kill':True,'old_ack_unknown_after_restart':True,
            'tail_recovered':True,'invalid_suffix_atomic':True,'retry_suppressed':True,'events':events}

FIRST_TIME,LATER_TIME=1700000100,1700000900

def timestamp_probe(rt):
    """Two contributions with DIFFERENT source times survive SIGKILL; the assembled event keeps the FIRST contribution's time."""
    import datetime
    source='assembly-time';first='START time first'
    for text,offset,seconds in ((first,0,FIRST_TIME),('trace',len(first.encode()),LATER_TIME)):
        status,response=post(rt,body(text,offset,seconds=seconds,source=source));assert status==200,(status,response)
    snapshot=rt['directory']/'state/assembly'
    pending=assembly_state.read(snapshot)['pending']
    assert any(p['text']==first+'\ntrace' for p in pending.values()),'both contributions must be durable before the kill'
    runtime.docker('kill','--signal','KILL',rt['name']);runtime.docker('start',rt['name'])
    rt['port'],rt['context']=runtime.ready(rt['name'],rt['directory'])
    events=wait_for(lambda: [e for e in runtime.read_events(rt['directory']/'events.ndjson') if e.get('source')==source])
    assert len(events)==1 and events[0]['event']==first+'\ntrace',events
    stamp=datetime.datetime.fromisoformat(events[0]['@timestamp'].replace('Z','+00:00')).timestamp()
    assert stamp==FIRST_TIME and float(events[0]['time'])==FIRST_TIME,(events[0].get('@timestamp'),events[0].get('time'))
    assert stamp!=LATER_TIME
    return {'first_contribution_time_retained':True,'first_time':FIRST_TIME,'later_time':LATER_TIME,'events':events}

def main():
    report={'artifact':runtime.artifact_info(),'validators':runtime.validators_info(),'rules':RULES,'mapping':MAPPING,'runs':[],'status':'fail'}
    def save():
        (runtime.EVIDENCE/'assembly.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
    def terminate(signum,frame):raise RuntimeError('assembly harness terminated by signal '+str(signum))
    signal.signal(signal.SIGTERM,terminate)
    rt=None
    try:
        flags,host=sender_network()
        for runtime_role,queue,mode in [('minimum','memory','full'),('minimum','persisted','none'),('latest','memory','id_only'),('latest','persisted','full')]:
            with socket.socket() as available:available.bind(('127.0.0.1',0));tcp_port=available.getsockname()[1]
            rt=runtime.start_tcp_runtime(runtime_role,tls=True,queue=queue,tcp_port=tcp_port,hec_metadata=mode,
                                         s2s_metadata_fields=MAPPING,s2s_line_breaker_rules=RULES)
            for transport in ('http','tcp'):
                for role in ('uf','hf'):
                    row={'runtime_role':runtime_role,'queue':queue,'mode':mode,'transport':transport,'sender':role,'status':'fail',
                         'receiver_image':runtime.P['logstash.'+runtime_role+'.image']}
                    report['runs'].append(row);real_sender(rt,role,transport,mode,flags,host,row)
                    save()
                    print('PASS',runtime_role,queue,mode,transport,role,flush=True)
            report.setdefault('recovery',[]).append({'runtime_role':runtime_role,'queue':queue,**crash_probe(rt)})
            save()
            report.setdefault('timestamp_recovery',[]).append({'runtime_role':runtime_role,'queue':queue,**timestamp_probe(rt)})
            save()
            if not finish_receiver(rt,report):raise RuntimeError('receiver cleanup failed')
            rt=None
        assert runtime.artifact_info()==report['artifact']
        report['status']='pass'
    except Exception as failure:report['error']=error_details(failure)
    finally:
        if rt is not None:finish_receiver(rt,report,diagnostics=True)
        if report.get('cleanup_errors'):report['status']='fail'
        save()
    if report['status']!='pass':print(json.dumps(report.get('error',{})),file=sys.stderr)
    return 0 if report['status']=='pass' else 1

if __name__=='__main__':sys.exit(main())
