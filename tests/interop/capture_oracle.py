#!/usr/bin/env python3
"""Capture oracle observations, never plugin-generated expectations.

Only the loopback disposable test server and public test tokens are used here.
Retain exact response bodies/status/headers and request bytes (base64).
"""
import base64
import http.client
import json
import time
import uuid
import ssl
import urllib.parse
import urllib.request
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOKENS = ['11111111-1111-4111-8111-111111111111',
          '22222222-2222-4222-8222-222222222222',
          '33333333-3333-4333-8333-333333333333',
          '44444444-4444-4444-8444-444444444444']
CHANNEL = '12345678-1234-4234-8234-123456789abc'

def request(method, path, body, headers):
    c = http.client.HTTPConnection('127.0.0.1', 18088, timeout=10)
    try:
        c.request(method, path, body, headers)
        r = c.getresponse()
        return dict(status=r.status, headers=r.getheaders(),
                    body=r.read().decode('utf-8', errors='strict'))
    finally:
        c.close()

def cases():
    for suffix in ('', '/event', '/raw', '/s2s', '/ack', '/health', '/unknown'):
        for alias in ('', '/1.0'):
            for trailing in ('', '/'):
                path = '/services/collector' + suffix + alias + trailing
                for method in ('POST', 'GET', 'PUT'):
                    body = b'{"acks":[0]}' if suffix == '/ack' else b'{"event":"route"}'
                    if suffix == '/raw': body = b'route\n'
                    if suffix == '/s2s': body = b''
                    yield 'route:' + method + ':' + path, method, path, body, {}
    values = ['"text"', '123', '123.45678901234567890123456789', '9223372036854775808',
              '{"message":"native","a.b":1}', '[1,"x"]', 'true', 'false', 'null', '""', '"  "']
    for v in values:
        yield 'event:' + v, 'POST', '/services/collector/event', ('{"event":'+v+'}').encode(), {}
    for name, b in {
        'missing': '{}', 'blank': ' ', 'empty': '', 'fields_nested': '{"event":"x","fields":{"n":{"k":1}}}',
        'fields_array': '{"event":"x","fields":{"a":[1,2]}}',
        'concat': '{"event":"one"}{"event":"two"}',
        'array': '[{"event":"one"},{"event":"two"}]',
        'bad_member_2': '{"event":"one"}{"host":"missing"}{"event":"three"}',
        'bad_json_2': '{"event":"one"}{"event":',
        'array_bad_member_2': '[{"event":"one"},{"host":"missing"},{"event":"three"}]',
        'array_bad_json_2': '[{"event":"one"},{"event":',
        'array_trailing': '[{"event":"one"}]junk',
        'empty_array_event': '{"event":[]}', 'empty_object_event': '{"event":{}}',
        'trailing': '{"event":"one"}junk', 'duplicate': '{"event":"first","event":"second"}',
        'index_null': '{"event":"x","index":null}', 'index_empty': '{"event":"x","index":""}',
        'index_denied': '{"event":"x","index":"_internal"}',
        'host_null': '{"event":"x","host":null}', 'host_number': '{"event":"x","host":2}',
        'time_string': '{"event":"x","time":"1700000000.123456789"}',
        'time_nanos': '{"event":"x","time":1700000000123456789}'
    }.items():
        yield name, 'POST', '/services/collector/event', b.encode(), {}
    for name, auth in [('missing', ''), ('bad', 'Splunk bogus'), ('malformed', 'Basic @@@'),
                       ('disabled', 'Splunk ' + TOKENS[3]),
                       ('basic_password', 'Basic ' + base64.b64encode(('user:'+TOKENS[0]).encode()).decode())]:
        yield 'auth:' + name, 'POST', '/services/collector/event', b'{"event":"auth"}', {'Authorization': auth}
    for token in TOKENS[:3]:
        yield 'query:'+token[:1], 'POST', '/services/collector/event?token='+token, b'{"event":"query"}', {'Authorization': ''}
    yield 'header_query_conflict', 'POST', '/services/collector/event?token='+TOKENS[2], b'{"event":"conflict"}', {'Authorization':'Splunk bogus'}
    for token in TOKENS[:2]:
        for channel in ('', 'invalid', CHANNEL):
            for mode in ('header', 'query'):
                path = '/services/collector/raw?sourcetype=hec_newline'
                h = {'Authorization':'Splunk '+token}
                if mode == 'header': h['X-Splunk-Request-Channel'] = channel
                else:
                    h['X-Splunk-Request-Channel']=None
                    path += '&channel='+channel
                yield 'raw:'+token[:1]+':'+channel+':'+mode, 'POST', path, b'one\r\n\ntwo\n \ntail', h
    for channel,query in [(CHANNEL,'invalid'),('invalid',CHANNEL),('',CHANNEL)]:
        yield 'channel-precedence:'+channel+':'+query, 'POST', '/services/collector/raw?channel='+query, b'line', {
            'Authorization':'Splunk '+TOKENS[1], 'X-Splunk-Request-Channel':channel}
    yield 'utf8_bad_prefix', 'POST', '/services/collector/event', b'{"event":"valid"}\xff', {}

def main():
    pins=dict(line.split('=',1) for line in (ROOT/'versions.properties').read_text().splitlines() if line and not line.startswith('#'))
    image=subprocess.check_output(['docker','inspect','hec-spec-oracle','--format','{{.Config.Image}}'],text=True,timeout=30).strip()
    if image!=pins['splunk.image']:raise RuntimeError('oracle image does not match approved pin')
    version=subprocess.check_output(['docker','exec','--user','splunk','hec-spec-oracle','/opt/splunk/bin/splunk','version'],text=True,timeout=30).strip()
    observations = []
    run_id = uuid.uuid4().hex
    for name, method, path, body, overrides in cases():
        headers = {'Authorization':'Splunk '+TOKENS[0], 'Content-Type':'application/json',
                   'X-Splunk-Request-Channel':CHANNEL}
        headers.update(overrides)
        headers={k:v for k,v in headers.items() if v is not None}
        if headers.get('Authorization') == '': headers.pop('Authorization')
        source = 'hec-oracle-' + run_id + '-' + str(len(observations))
        path += ('&' if '?' in path else '?') + urllib.parse.urlencode({'source':source})
        if method == 'GET': body = b''
        response = request(method, path, body, headers)
        observations.append(dict(name=name, method=method, path=path,
            request_body_base64=base64.b64encode(body).decode(),
            request_headers=headers, response=response,
            expected_source=source))
        print(name, response['status'], response['body'], flush=True)
    ack_headers = {'Authorization':'Splunk '+TOKENS[1], 'X-Splunk-Request-Channel':CHANNEL}
    accepted = request('POST', '/services/collector/event', b'{"event":"ack-poll"}', ack_headers)
    ack_id = json.loads(accepted['body'])['ackId']
    time.sleep(10)
    for value in [[ack_id, ack_id], [ack_id], [999999], ['0'], [0.5], [], None]:
        body = json.dumps({'acks': value}).encode()
        response = request('POST','/services/collector/ack',body,ack_headers)
        observations.append(dict(name='ack-poll:'+repr(value), method='POST',
            path='/services/collector/ack', request_body_base64=base64.b64encode(body).decode(),
            request_headers=ack_headers, response=response))
        print('ack-poll', value, response, flush=True)
    query = 'search index=main earliest=0 source="hec-oracle-'+run_id+'-*" | table source _raw host sourcetype'
    data = urllib.parse.urlencode({'search':query, 'output_mode':'json'}).encode()
    req = urllib.request.Request('https://127.0.0.1:18089/services/search/jobs/export', data=data,
        headers={'Authorization':'Basic '+base64.b64encode(b'admin:HecOracle-Test-Only-487!').decode()})
    # Disposable oracle management cert is self-signed. Plugin TLS tests use verification.
    with urllib.request.urlopen(req, context=ssl._create_unverified_context(), timeout=60) as r:
        indexed = [json.loads(line)['result'] for line in r if b'"result"' in line]
    for observation in observations:
        if 'expected_source' in observation:
            matches = [e for e in indexed if e.get('source') == observation['expected_source']]
            observation['accepted_event_count'] = len(matches)
            observation['indexed_values'] = matches
    out = ROOT/'tests/interop/evidence'
    out.mkdir(exist_ok=True)
    (out/'oracle-http.json').write_text(json.dumps(dict(
        source='real Splunk; not plugin expectations', version=version,
        image=image,
        architecture='linux/amd64', run_id=run_id, observations=observations), indent=2)+'\n')

if __name__ == '__main__': main()
