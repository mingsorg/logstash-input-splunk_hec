#!/usr/bin/env python3
"""Offline interpretation of this project's own complete real TCP captures.

Wire facts are checked against captured client/server bytes and indexed fixture
values. This is analysis evidence, not a synthetic qualification of a TCP input.
"""
import base64
import argparse
from collections import Counter,defaultdict
import hashlib
import json
from pathlib import Path
import struct
import zlib

ROOT=Path(__file__).resolve().parents[2]


class Reader:
    def __init__(self,data,order='>'):self.data=data;self.pos=0;self.order=order
    def take(self,n):
        if n<0 or n>len(self.data)-self.pos:raise ValueError('truncated at '+str(self.pos))
        result=self.data[self.pos:self.pos+n];self.pos+=n;return result
    def byte(self):return self.take(1)[0]
    def u(self):
        n=0
        for shift in range(0,70,7):
            b=self.byte()
            if shift==63 and b>1:raise ValueError('varint overflow')
            n|=(b&127)<<shift
            if not b&128:return n
        raise ValueError('varint overflow')
    def blob(self):return self.take(self.u())
    def text(self):return self.blob().decode()
    def nullable(self):
        n=self.u();return self.take(n-1).decode() if n else None
    def be(self):return struct.unpack(self.order+'I',self.take(4))[0]
    def kv(self):
        frame=self.take(self.be());order='>'
        if len(frame)>=7 and frame[4]&15==8 and ((frame[4]<<8)|frame[5])%31==0:
            if struct.unpack_from('>I',frame)[0]!=len(frame)-4 or frame[-1]!=0:raise ValueError('compressed wrapper')
            frame=zlib.decompress(frame[4:-1]);order='<'
        body=Reader(frame,order);pairs={}
        for _ in range(body.be()):
            key=body.take(body.be()).rstrip(b'\0').decode()
            value=body.take(body.be()).rstrip(b'\0').decode()
            pairs[key]=value
        if body.be()!=0 or body.take(body.be())!=b'_raw\0' or body.pos!=len(body.data):raise ValueError('invalid KV trailer')
        return pairs


def strip(value,prefix):return value[len(prefix):] if value and value.startswith(prefix) else value


def client(data):
    r=Reader(data)
    signature=r.take(128).rstrip(b'\0').decode()
    hostname=r.take(256).rstrip(b'\0').decode()
    management=r.take(16).rstrip(b'\0').decode()
    if signature!='--splunk-cooked-mode-v3--':raise ValueError('unsupported greeting '+signature)
    capabilities=r.kv();info=r.kv()
    if 'v4=1' not in info.get('__s2s_capabilities',''):raise ValueError('capture did not switch to compact v4')
    # Latest TLS senders were observed using the F9 stream although their capability string
    # said compression=0, so the stream itself decides; a requested compression must be present.
    requested='compression=1' in capabilities.get('__s2s_capabilities','')
    stream_compressed=r.pos<len(data) and data[r.pos]==0xf9
    if stream_compressed:r.byte()
    elif requested:raise ValueError('missing continuous zlib marker')
    if stream_compressed:
        compressed=r.take(len(data)-r.pos);inflater=zlib.decompressobj()
        expanded=inflater.decompress(compressed,64*1024*1024+1)
        if len(expanded)>64*1024*1024 or inflater.unconsumed_tail or inflater.unused_data:raise ValueError('unbounded/trailing compressed capture')
        if not inflater.eof and not compressed.endswith(b'\0\0\xff\xff'):raise ValueError('truncated compressed capture')
        data=expanded;r=Reader(data)
    channels={};opcodes=Counter();flags=Counter();tags=Counter();ids=[];samples=[];max_raw=0;clones=[];zero_records=[]
    while r.pos<len(data):
        start=r.pos;op=r.byte();opcodes[f'{op:02x}']+=1
        try:
            if op==0xff:r.text()
            elif op in (0xfe,0xf8):
                parent=r.u() if op==0xf8 else None
                channel=r.u();values=[r.nullable() for _ in range(4)]
                columns=[r.text() for _ in range(r.u())]
                clone_evidence={'prefix':parent,'channel_id':channel,'wire_slots':list(values),'prior_channel_exists':parent in channels}
                inherited=channels.get(parent,{})
                values=[v if v is not None else inherited.get(k) for v,k in zip(values,('source','host','sourcetype','channel'))]
                channels[channel]=dict(zip(('source','host','sourcetype','channel'),values),columns=columns)
                if parent is not None:clones.append(clone_evidence)
            elif op==0xfd:channels.pop(r.u(),None)
            elif op==0xfc:
                channel=r.u();f=r.u();flags[hex(f)]+=1
                if channel not in channels:raise ValueError('unopened channel '+str(channel))
                stream=offset=suboffset=event_id=seconds=None
                if f&2:stream,offset,suboffset=r.u(),r.u(),r.u()
                if f&4:event_id=r.u();ids.append(event_id)
                if f&8:seconds=r.u()
                fields={};metadata={};references=[];metrics=[];date=[]
                def add(key,value):
                    if key not in fields:fields[key]=value
                    elif isinstance(fields[key],list):fields[key].append(value)
                    else:fields[key]=[fields[key],value]
                for _ in range(r.u()):
                    tag=r.u();tags[hex(tag)]+=1
                    if tag==4:
                        key=r.text();metadata[key]=r.text()
                    elif tag==0x46:
                        # Observed only on records retransmitted by the sender: U(marker) S("resent").
                        marker=r.u();metadata['resent:'+str(marker)]=r.text()
                    elif tag&0xc0==0x40:date.append((tag,r.u(),r.u()))
                    elif tag&1:
                        key=r.text() if tag&2 else channels[channel]['columns'][r.u()]
                        kind=(tag>>2)&7
                        if kind==0:add(key,r.u())
                        elif kind==1:add(key,r.text())
                        elif kind==2:
                            value=r.u();add(key,{60:'null',61:False,62:True}.get(value,value))
                        elif kind in (3,6):
                            reference=(r.u(),r.u(),kind==6);references.append((key,reference));add(key,reference)
                        elif kind==4:
                            at=r.u()
                            if tag&0x180:r.u();r.u()
                            metrics.append((key,at))
                        else:raise ValueError('unknown kind '+str(kind))
                    else:raise ValueError('unknown field tag '+hex(tag))
                values=r.blob() if f&0x10000 else None
                raw=r.blob();max_raw=max(max_raw,len(raw))
                for key,at in metrics:add(key.removeprefix('metric_name:'),struct.unpack_from('<d',values,at)[0])
                def resolve(value):
                    if isinstance(value,tuple):
                        at,n,escaped=value
                        if at+n>len(raw):raise ValueError('bad raw reference')
                        text=raw[at:at+n].decode()
                        return json.loads('"'+text+'"') if escaped else text
                    if isinstance(value,list):return [resolve(item) for item in value]
                    return value
                fields={key:resolve(value) for key,value in fields.items()}
                meta=channels[channel]
                if event_id==0:zero_records.append({'flags':hex(f),'channel':channel,'metadata':metadata,'raw':raw.decode(),'fields':fields})
                source=strip(metadata.get('MetaData:Source') or meta['source'],'source::')
                if source and source.startswith('/tmp/hec-source.'):
                    samples.append({'source':source,'host':strip(metadata.get('MetaData:Host') or meta['host'],'host::'),
                        'sourcetype':strip(metadata.get('MetaData:Sourcetype') or meta['sourcetype'],'sourcetype::'),
                        'index':metadata.get('_MetaData:Index','main'),'flags':hex(f),'event_id':event_id,
                        'stream_id':stream,'offset':offset,'suboffset':suboffset,'seconds':seconds,
                        'date_parts':date,'fields':fields,'raw':raw.decode()})
            else:raise ValueError('unknown opcode '+hex(op))
        except Exception as error:raise ValueError('record at '+str(start)+': '+str(error)+'; next '+data[r.pos:r.pos+32].hex()) from error
    return {'hostname':hostname,'signature':signature,'management_port':management,'capabilities':capabilities,
        'forwarder_info':info,'opcodes':dict(opcodes),'flags':dict(flags),'field_tags':dict(tags),
        'event_ids':ids,'source_records':samples,'zero_id_records':zero_records,'max_raw_bytes':max_raw,'clones':clones,'fully_consumed':r.pos==len(data)}


def server(data):
    r=Reader(data);capabilities=r.kv();acks=[]
    while r.pos<len(data):
        op=r.byte()
        if op==0xfb:lo=hi=r.u()
        elif op==0xfa:lo,hi=r.u(),r.u()
        else:raise ValueError('unknown reverse opcode '+hex(op))
        if hi<lo:raise ValueError('reversed ACK range')
        acks.append({'opcode':hex(op),'lo':lo,'hi':hi})
    return {'capabilities':capabilities,'acks':acks}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--compressed',action='store_true');args=parser.parse_args()
    suffix='-compressed' if args.compressed else ''
    path=ROOT/('tests/tcp/evidence/tcp-capture'+suffix+'.json')
    capture=json.loads(path.read_text())
    if any(row.get('truncated') for row in capture['traffic']) or capture.get('dropped_observations'):
        raise ValueError('capture is truncated; it cannot establish complete framing')
    streams=defaultdict(bytearray)
    for row in capture['traffic']:
        if 'data_base64' in row:streams[(row['connection'],row['direction'])].extend(base64.b64decode(row['data_base64']))
    report={'capture_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'connections':[]}
    fixture_dir=ROOT/'tests/tcp/fixtures';fixture_dir.mkdir(parents=True,exist_ok=True)
    manifests=[];observed=Counter()
    for connection in sorted({identity for identity,direction in streams}):
        forward=client(bytes(streams[(connection,'sender')]))
        reverse=server(bytes(streams[(connection,'receiver')]))
        forward['connection']=connection;forward['reverse']=reverse
        # The observed terminal/heartbeat record has ID zero; the real receiver
        # does not acknowledge it. Every positive ID in these captures is covered.
        forward['all_event_ids_acknowledged']=all(any(ack['lo']<=value<=ack['hi'] for ack in reverse['acks']) for value in forward['event_ids'] if value)
        for event in forward['source_records']:
            lines=[event['raw']] if int(event['flags'],16)&0x40 else event['raw'].splitlines()
            for line in lines:
                if line:observed[(event['source'],event['host'],event['sourcetype'],event['index'],line)]+=1
        client_bytes=bytes(streams[(connection,'sender')]);server_bytes=bytes(streams[(connection,'receiver')])
        client_name=hashlib.sha256(client_bytes).hexdigest()+'-client.bin'
        server_name=hashlib.sha256(server_bytes).hexdigest()+'-server.bin'
        (fixture_dir/client_name).write_bytes(client_bytes);(fixture_dir/server_name).write_bytes(server_bytes)
        manifests.append({'client':client_name,'server':server_name,'hostname':forward['hostname'],
            'source_records':forward['source_records'],'ids':forward['event_ids'],'compressed':args.compressed,
            'positive_ids_acknowledged':forward['all_event_ids_acknowledged']})
        report['connections'].append(forward)
        print(json.dumps({'connection':connection,'host':forward['hostname'],'opcodes':forward['opcodes'],
            'flags':forward['flags'],'source_records':len(forward['source_records']),
            'acked':forward['all_event_ids_acknowledged'],'max_raw_bytes':forward['max_raw_bytes']},indent=2))
    expected=Counter((e['source'],e['host'],e['sourcetype'],e['index'],e['_raw']) for sender in capture['senders'] for e in sender['oracle_indexed_events'])
    if observed!=expected:raise ValueError('decoded source values/metadata differ from the real oracle')
    if not all(c['all_event_ids_acknowledged'] for c in report['connections']):raise ValueError('unacknowledged positive event IDs in capture')
    report['source_values_match_oracle']=True
    (ROOT/('tests/tcp/evidence/decoded-capture'+suffix+'.json')).write_text(json.dumps(report,indent=2)+'\n')
    (fixture_dir/('manifest'+suffix+'.json')).write_text(json.dumps(manifests,indent=2)+'\n')


if __name__=='__main__':main()
