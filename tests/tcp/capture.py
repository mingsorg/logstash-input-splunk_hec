#!/usr/bin/env python3
"""Bounded, transparent TCP spike against an owned real Splunk receiver.

Run inside the interop driver (host networking) with --receiver IP:9997.
This records transport evidence; it does NOT qualify or implement a TCP input.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import selectors
import socket
import socketserver
import subprocess
import sys
import threading
import time
import uuid

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests/interop'))
import runtime
from senders import sender_ready, sender_network, sender_bootstrap_args
from oracle_query import source_events


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receiver',required=True,help='Owned oracle bridge IP and TCP port')
    parser.add_argument('--port',type=int,default=18097)
    parser.add_argument('--timeout',type=int,default=600)
    parser.add_argument('--compressed',action='store_true',help='Capture the real sender compression mode separately')
    args=parser.parse_args()
    host,port=args.receiver.rsplit(':',1)
    output=ROOT/'tests/tcp/evidence'
    output.mkdir(parents=True,exist_ok=True)
    observations=[]
    lock=threading.Lock()
    retained=0
    # Fresh HF diagnostic traffic exceeded the original 4-MiB total cap before
    # its fixture records. Keep a finite 32-MiB budget and report any truncation.
    cap=32*1024*1024
    max_observations=4096
    dropped=0
    byte_counts={'sender':0,'receiver':0}
    connections=set()
    connection_slots=threading.Semaphore(16)
    stopping=threading.Event()

    class Relay(socketserver.BaseRequestHandler):
        def handle(self):
            nonlocal retained,dropped
            identifier=uuid.uuid4().hex
            if not connection_slots.acquire(blocking=False):return
            target=None
            try:
                with socket.create_connection((host,int(port)),timeout=10) as target:
                    target.settimeout(10)
                    self.request.settimeout(10)
                    with lock:connections.update((self.request,target))
                    with selectors.DefaultSelector() as selector:
                        selector.register(self.request,selectors.EVENT_READ,('sender',target))
                        selector.register(target,selectors.EVENT_READ,('receiver',self.request))
                        while not stopping.is_set():
                            for key,_ in selector.select(.25):
                                body=key.fileobj.recv(65536)
                                if not body:return
                                direction,destination=key.data
                                with lock:
                                    byte_counts[direction]+=len(body)
                                    keep=body[:max(0,cap-retained)]
                                    if len(observations)<max_observations:
                                        retained+=len(keep)
                                        observations.append(dict(connection=identifier,direction=direction,
                                            sequence=len(observations),bytes=len(body),sha256=hashlib.sha256(body).hexdigest(),
                                            data_base64=base64.b64encode(keep).decode(),truncated=len(keep)!=len(body)))
                                    else:dropped+=1
                                destination.sendall(body)
            except OSError as error:
                with lock:
                    if len(observations)<max_observations:observations.append(dict(connection=identifier,error=type(error).__name__))
                    else:dropped+=1
            finally:
                with lock:connections.discard(self.request);connections.discard(target)
                connection_slots.release()

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address=True
        daemon_threads=True

    senders=[]
    result={'status':'observed-only','tcp_input_qualified':False,'receiver':args.receiver,
            'configuration':{'useACK':True,'compressed':args.compressed,'tls':False},'senders':[],
            'limitations':['TCP decoder, receiver-side ACK generation, TLS, compression and induced retries are not implemented or qualified.']}
    server=Server(('0.0.0.0',args.port),Relay)
    thread=threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    try:
        network_flags,receiver_host=sender_network()
        for role,image in [('uf',runtime.P['uf.image']),('hf',runtime.P['splunk.image'])]:
            name='hec-tcp-spike-'+role+'-'+uuid.uuid4().hex[:8]
            senders.append(name)
            with lock:before=len(observations);before_bytes=dict(byte_counts)
            runtime.docker('run','-d','--name',name,'--platform','linux/amd64','--user','root',
                *sender_bootstrap_args(name),
                *network_flags,
                '-e','SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com',
                '-e','HEC_TRANSPORT=tcp','-e','HEC_TCP_RECEIVER='+receiver_host+':'+str(args.port),
                '-e','HEC_TCP_COMPRESSED='+str(args.compressed).lower(),
                '-v',str(ROOT/'tests/interop/sender_setup.py')+':/tmp/hec-sender-setup.py:ro',
                '--entrypoint','/usr/bin/python3',image,'/tmp/hec-sender-setup.py')
            sender_ready(name,args.timeout)
            hostname=runtime.docker('inspect',name,'--format','{{.Config.Hostname}}')
            deadline=time.monotonic()+90
            indexed=[]
            while time.monotonic()<deadline:
                indexed=source_events(hostname)
                if len(indexed)>=6:break
                time.sleep(1)
            if len(indexed)!=6:raise RuntimeError(role+' TCP oracle did not index exactly six source events: '+str(indexed))
            # Retain the reverse-channel ACKs following real receiver processing.
            time.sleep(3)
            home='/opt/splunkforwarder' if role=='uf' else '/opt/splunk'
            runtime.docker('exec','--user','splunk',name,home+'/bin/splunk','stop',timeout=90)
            time.sleep(1) # drain orderly close-channel records before snapshotting
            with lock:rows=list(observations[before:])
            result['senders'].append(dict(role=role,image=image,
                hostname=hostname,oracle_indexed_events=indexed,
                connection_ids=sorted({row['connection'] for row in rows}),
                version=runtime.docker('exec','--user','splunk',name,home+'/bin/splunk','version'),
                sent_bytes=byte_counts['sender']-before_bytes['sender'],
                received_bytes=byte_counts['receiver']-before_bytes['receiver']))
            runtime.docker('rm','-f','-v',name)
            senders.remove(name)
        result['bidirectional_observed']=all(s['sent_bytes'] and s['received_bytes'] for s in result['senders'])
        print(json.dumps({k:v for k,v in result.items() if k!='traffic'},indent=2),flush=True)
        return 0 if result['bidirectional_observed'] else 1
    except Exception as error:
        result['status']='capture-failed'
        result['error']=str(error)
        raise
    finally:
        stopping.set()
        server.shutdown();server.server_close();thread.join(5)
        with lock:
            for connection in connections:
                try:connection.shutdown(socket.SHUT_RDWR)
                except OSError:pass
            result['traffic']=observations
            result['dropped_observations']=dropped
            result['retained_bytes']=retained
        (output/('tcp-capture-compressed.json' if args.compressed else 'tcp-capture.json')).write_text(json.dumps(result,indent=2)+'\n')
        for name in senders:subprocess.run(['docker','rm','-f','-v',name],capture_output=True,timeout=60)


if __name__=='__main__':sys.exit(main())
