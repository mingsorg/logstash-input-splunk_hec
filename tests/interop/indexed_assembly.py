#!/usr/bin/env python3
"""Fresh UF/HF -> exact gem -> Logstash HTTP output -> owned Splunk indexer proof."""
from collections import Counter
from datetime import datetime, timezone
from decimal import Decimal
import base64
import hashlib
import json
import socket
import ssl
import subprocess
import sys
import urllib.parse
import urllib.request
import urllib.error
import uuid

import assembly
import runtime
from senders import sender_network, sender_ready
from start_oracle import create_oracle
from metadata_fields import finish_receiver, error_details

def splunk_epoch(text):
    """Splunk search export renders _time as 'YYYY-MM-DD HH:MM:SS.mmm GMT'."""
    moment=datetime.strptime(text,'%Y-%m-%d %H:%M:%S.%f GMT').replace(tzinfo=timezone.utc)
    return Decimal(int(moment.timestamp()))+Decimal(moment.microsecond)/Decimal(1000000)

def query(search):
    data=urllib.parse.urlencode({'search':search,'output_mode':'json'}).encode()
    request=urllib.request.Request('https://127.0.0.1:18089/services/search/jobs/export',data=data,
        headers={'Authorization':'Basic '+base64.b64encode(b'admin:HecOracle-Test-Only-487!').decode()})
    with urllib.request.urlopen(request,context=ssl._create_unverified_context(),timeout=60) as response:
        return [json.loads(line)['result'] for line in response if b'"result"' in line]

def main():
    report={'artifact':runtime.artifact_info(),'validators':runtime.validators_info(),'runs':[],'status':'fail'};rt=None;indexer=None
    marker='assembly-'+uuid.uuid4().hex
    try:
        existing=subprocess.run(['docker','inspect','hec-spec-oracle'],capture_output=True,timeout=30)
        if existing.returncode==0:raise RuntimeError('owned indexer name already exists; refusing to take ownership')
        indexer=create_oracle();sender_ready('hec-spec-oracle',900)
        def ready():
            try:return query('| makeresults | eval ready="yes"')
            except (OSError,urllib.error.HTTPError):return None
        assembly.wait_for(ready,300)
        flags,host=sender_network()
        destination='http://'+host+':18088/services/collector/event'
        forwarding='''
filter { ruby { code => 'require "digest"; values = {}; %w[event time host source sourcetype index fields].each { |key| value = event.get(key); values[key] = value unless value.nil? }; original = values["fields"] ? values["fields"].dup : {}; values["fields"] = original.dup; values["fields"]["hec_qualification_digest"] = Digest::SHA256.hexdigest([event.get("event"), event.get("source"), event.get("sourcetype")].join("\\0")); values["fields"]["hec_qualification_fields_json"] = LogStash::Json.dump(original); values["fields"]["hec_qualification_route"] = "'''+marker+'''"; %w[path salt].each { |key| value = event.get("[s2s_metadata][#{key}]"); values["fields"]["hec_qualification_#{key}"] = value unless value.nil? }; event.set("[@metadata][hec_forward]", LogStash::Json.dump(values))' } }
output { http { url => "'''+destination+'''" http_method => "post" format => "message" content_type => "application/json"
  headers => { "Authorization" => "Splunk '''+runtime.TOKEN+'''" } message => "%{[@metadata][hec_forward]}" } }
'''
        with socket.socket() as available:available.bind(('127.0.0.1',0));port=available.getsockname()[1]
        rt=runtime.start_tcp_runtime('latest',tls=True,queue='persisted',tcp_port=port,hec_metadata='full',s2s_metadata_fields=assembly.MAPPING,
                                    s2s_line_breaker_rules=assembly.RULES,extra_pipeline=forwarding)
        expected=[]
        for transport in ('http','tcp'):
            for role in ('uf','hf'):
                row={'role':role,'transport':transport,'route_marker':marker,'status':'fail'};report['runs'].append(row)
                assembly.real_sender(rt,role,transport,'full',flags,host,row)
                for events in row['events'].values():expected.extend(events)
        field_names=sorted({key for event in expected for key in event.get('fields',{})}-{'host'})
        projected=' '.join('"'+name.replace('\\','\\\\').replace('"','\\"')+'"' for name in field_names)
        search='search index=main earliest=0 latest=+10y hec_qualification_route="'+marker+'" | table _raw host source sourcetype index _time hec_qualification_route hec_qualification_path hec_qualification_salt hec_qualification_digest hec_qualification_fields_json '+projected
        indexed=assembly.wait_for(lambda: (rows if len(rows:=query(search))>=len(expected) else None),300)
        report['indexed_events']=indexed
        def identity(event,indexed=False):
            return (event['_raw' if indexed else 'event'],event['source'],event['sourcetype'])
        assert Counter(identity(e) for e in expected)==Counter(identity(e,True) for e in indexed),(expected,indexed)
        def indexed_only_match(row,event):
            """Values that exist ONLY as forwarded indexed fields (never in _raw): per-event digest and the exact ordered fields."""
            digest=hashlib.sha256('\0'.join((event['event'],event['source'],event['sourcetype'])).encode()).hexdigest()
            if row.get('hec_qualification_digest')!=digest:return False
            return json.loads(row.get('hec_qualification_fields_json') or 'null')==event.get('fields',{})
        def native_values_match(row,event,hosts):
            if event['host'] not in hosts or row['index']!=event['index']:return False
            if abs(splunk_epoch(row['_time'])-Decimal(str(event['time'])))>=Decimal('0.001'):return False # Splunk export is millisecond precision
            for key,value in event.get('fields',{}).items():
                if key=='host':continue # explicitly verified as the native/indexed multivalue union above
                observed=row.get(key)
                # Search-time JSON extraction of identical _raw may repeat these values; the exact ordered
                # authority is hec_qualification_fields_json (indexed-only), checked separately.
                values=observed if isinstance(observed,list) else [observed]
                if list(dict.fromkeys(values))!=[str(v) for v in (value if isinstance(value,list) else [value])]:return False
            for key,value in event.get('s2s_metadata',{}).items():
                if key in ('path','salt') and row.get('hec_qualification_'+key)!=value:return False
            return indexed_only_match(row,event)
        controls=0
        for row in indexed:
            assert row['hec_qualification_route']==marker
            candidates=[e for e in expected if identity(e)==identity(row,True)]
            hosts=row['host'] if isinstance(row['host'],list) else [row['host']]
            # The structured JSON fixture deliberately has an indexed field named host
            # as well as native envelope host. Splunk search reports their multivalue union.
            assert any(e['host'] in hosts and set(hosts)<=set([e['host'],e.get('fields',{}).get('host',e['host'])]) for e in candidates),row
            assert any(native_values_match(row,event,hosts) for event in candidates),(row,candidates)
            # Negative controls: the same assertion MUST reject a row lacking the indexed-only values, one whose ordered
            # fields differ, and one reduced to what _raw alone could supply.
            stripped={k:v for k,v in row.items() if k not in ('hec_qualification_digest','hec_qualification_fields_json')}
            altered=dict(row,hec_qualification_fields_json=json.dumps({'forged':['value']}))
            raw_only=dict(stripped,**{k:v for k,v in row.items() if k.startswith('a.b')})
            for control in (stripped,altered,raw_only):
                assert not any(native_values_match(control,event,hosts) for event in candidates),('negative control accepted',control)
                controls+=1
        report['negative_controls']={'rejected':controls,'rows':len(indexed),'kinds':['digest-and-fields-removed','ordered-fields-forged','raw-derivable-values-only']}
        report.update(status='pass',indexer_image=runtime.P['splunk.image'],receiver_image=runtime.P['logstash.latest.image'],
                       indexed_events=indexed,route_marker=marker,search=search,
                      note='JSON fixture fields may repeat in search results: forwarded indexed fields plus Splunk default search-time extraction of identical _raw; assertions require per-event indexed-only digest and exact ordered fields (hec_qualification_digest / hec_qualification_fields_json, absent from _raw); legacy fields are compared de-duplicated and three negative controls per row must be rejected.',
                       scope='live UF/HF HTTP/TCP through packaged input and Logstash HTTP output; exact raw, source, host, sourcetype, index, _time (millisecond export precision), indexed multivalues and explicitly projected selected metadata; projection is qualification output configuration, not automatic core forwarding')
        assert report['artifact']==runtime.artifact_info()
    except Exception as error:report['error']=error_details(error)
    finally:
        if rt is not None:finish_receiver(rt,report,diagnostics=report['status']!='pass')
        if indexer:
            try:runtime.docker('rm','-f','-v',indexer)
            except Exception as error:report.setdefault('cleanup_errors',[]).append(error_details(error))
        if report.get('cleanup_errors'):report['status']='fail'
        (runtime.EVIDENCE/'indexed-assembly.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
    if report['status']!='pass':print(report.get('error',{}),file=sys.stderr)
    return 0 if report['status']=='pass' else 1

if __name__=='__main__':sys.exit(main())
