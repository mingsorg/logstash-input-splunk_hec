#!/usr/bin/env python3
"""Finite black-box HTTPS checks, also invoked against each packaged runtime.

This sends test events. Supply a dedicated test token through the named environment
variable. Transport trust and hostname verification are always enabled.
"""
import argparse
import gzip
import http.client
import json
import os
import ssl
import urllib.parse
import uuid

def check(base,ca,token):
    url=urllib.parse.urlsplit(base)
    if url.scheme!='https' or url.path not in ('','/'):
        raise ValueError('base must be an HTTPS origin')
    context=ssl.create_default_context(cafile=str(ca))
    channel=str(uuid.uuid4())
    observations=[]
    def request(method,path,body=None,extra=None):
        connection=http.client.HTTPSConnection(url.hostname,url.port or 443,context=context,timeout=15)
        try:
            headers={'Authorization':'Splunk '+token,'X-Splunk-Request-Channel':channel}
            headers.update(extra or {})
            connection.request(method,'/services/collector/'+path,body,headers)
            response=connection.getresponse();value=json.loads(response.read())
            observations.append({'method':method,'path':path,'status':response.status,'response':value})
            return response.status,value
        finally:connection.close()
    assert request('GET','health')==(200,{'text':'HEC is healthy','code':17})
    status,value=request('POST','event/1.0',b'{"event":"black-box HTTPS"}')
    assert status==200 and isinstance(value.get('ackId'),int),(status,value)
    ack=value['ackId']
    assert request('POST','ack',json.dumps({'acks':[ack,ack]}))==(200,{'acks':{str(ack):True}})
    assert request('POST','ack',json.dumps({'acks':[ack]}))==(200,{'acks':{str(ack):False}})
    status,value=request('POST','raw',gzip.compress(b'one\r\n\ntwo\n \ntail'),{'Content-Encoding':'gzip'})
    assert status==200 and value['code']==0,(status,value)
    status,value=request('POST','event',b'{"event":"prefix"}{"host":"missing"}')
    assert status==400 and value=={'text':'Event field is required','code':12,'invalid-event-number':1},(status,value)
    status,value=request('POST','s2s',b'\xf9bad-compression')
    assert status==400 and value=={'text':'Invalid data format','code':6},(status,value)
    return {'status':'pass','verified_https':True,'observations':observations}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url',required=True)
    parser.add_argument('--ca',required=True)
    parser.add_argument('--token-env',default='HEC_TOKEN')
    args=parser.parse_args()
    print(json.dumps(check(args.base_url,args.ca,os.environ[args.token_env]),indent=2))

if __name__=='__main__':main()
