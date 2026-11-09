#!/usr/bin/env python3
"""Exact installed-gem Node Stats, reset/replay, disabled and blocked-queue checks."""
import concurrent.futures
import http.client
import json
import math
import random
import socket
import statistics
import struct
import subprocess
import time
import uuid
import runtime
from assembly import body, wait_for, string, varint


def flatten(value, prefix=''):
    result = {}
    for key, item in value.items():
        name = prefix + key
        if isinstance(item, dict):
            result.update(flatten(item, name + '.'))
        else:
            result[name] = item
    return result


def schema():
    result = {f'http.{route}.{outcome}' for route in ('event', 'raw', 's2s', 'ack', 'health', 'unknown')
              for outcome in ('success', 'unauthorized', 'forbidden', 'invalid', 'busy', 'internal')}
    result.update(('http.connection_rejected', 'http.response_failures', 'tcp.connection_accepted', 'tcp.connection_rejected',
                   'tcp.connection_closed', 'tcp.connection_failures', 'tcp.response_failures', 'tcp.data.success', 'tcp.data.failure',
                   'tcp.control.success', 'tcp.control.failure', 'assembly.enabled', 'assembly.blocked', 'assembly.pending',
                   'assembly.outbox', 'assembly.receipts', 'assembly.live_bytes', 'assembly.reserved_bytes', 'assembly.quota_bytes',
                   'assembly.utilization_basis_points', 'assembly.physical_bytes_last_observed', 'assembly.journal_bytes_last_observed',
                   'assembly.contributions', 'last_durable_acceptance_epoch_millis', 'last_handoff_epoch_millis', 'last_commit_epoch_millis', 'handoff.active'))
    result.update('assembly.flush.' + reason for reason in ('timeout', 'metadata_conflict', 'structured_transition',
                  'coordinate_gap_or_reordering', 'reordering', 'new_start'))
    for kind in ('http_event', 'http_raw', 'http_s2s', 'tcp', 'assembly_direct', 'outbox'):
        result.add(f'handoff.{kind}.returned')
        result.update(f'handoff.{kind}.{suffix}' for suffix in ('attempts', 'count', 'failures', 'total_nanos'))
    result.update(f'store.{kind}.{suffix}' for kind in ('capacity', 'commit', 'publication', 'compaction', 'fsync')
                  for suffix in ('attempts', 'count', 'failures', 'total_nanos'))
    return result


def request(port, path, data=None, token=runtime.TOKEN):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
    headers = {'X-Splunk-Request-Channel': runtime.CHANNEL}
    if token is not None:
        headers['Authorization'] = 'Splunk ' + token
    try:
        connection.request('GET' if data is None else 'POST', '/services/collector/' + path, data, headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def tcp_probe(port):
    def frame(pairs):
        def text(s):
            data=s.encode()+b'\0'
            return struct.pack('>I',len(data))+data
        data=struct.pack('>I',len(pairs))+b''.join(text(k)+text(v) for k,v in pairs.items())+b'\0'*4+text('_raw')
        return struct.pack('>I',len(data))+data
    def exact(peer,length):
        data=b''
        while len(data)<length:
            chunk=peer.recv(length-len(data))
            if not chunk:raise EOFError('short TCP reply')
            data+=chunk
        return data
    greeting=bytearray(400)
    for offset,text in ((0,b'--splunk-cooked-mode-v3--'),(128,b'metrics-probe'),(384,b'8089')):
        greeting[offset:offset+len(text)]=text
    with socket.create_connection(('127.0.0.1',port),timeout=10) as peer:
        peer.settimeout(10)
        peer.sendall(greeting+frame({'__s2s_capabilities':'ack=1;compression=0'}))
        assert b'v4=true' in exact(peer,struct.unpack('>I',exact(peer,4))[0])
        peer.sendall(frame({'_guid':'00000000-0000-4000-8000-000000000005','__s2s_capabilities':'v4=1;pl=7'}))
        metadata=b'\xfe\x01'+b''.join(string(v,True) for v in ('source::metrics','host::metrics','sourcetype::unmatched','channel'))+b'\0'
        def event(event_id,payload):
            return b'\xfc\x01\x0e'+b''.join(varint(v) for v in (7,event_id-1,event_id,event_id,1700000000))+b'\0'+varint(len(payload))+payload
        peer.sendall(metadata+event(1,b'tcp one\ntcp two'))
        assert exact(peer,2)==b'\xfb\x01'
        peer.sendall(event(2,b'\xff'))
        assert peer.recv(1)==b'', 'invalid UTF-8 record was acknowledged'


def overhead(enabled_port,disabled_port):
    payload=(b'metrics overhead synthetic line\n')*32
    for _ in range(10):
        for port in (enabled_port,disabled_port):assert request(port,'raw',payload)[0]==200
    samples={'enabled':[],'disabled':[]}
    rng=random.Random(5)
    rounds=[]
    for round_number in range(3):
        current={'enabled':[],'disabled':[]}
        for _ in range(60):
            order=[('enabled',enabled_port),('disabled',disabled_port)];rng.shuffle(order)
            for mode,port in order:
                start=time.perf_counter_ns();assert request(port,'raw',payload)[0]==200
                elapsed=time.perf_counter_ns()-start
                samples[mode].append(elapsed);current[mode].append(elapsed)
        rounds.append({'round':round_number+1,'samples_ns':current,'median_overhead_percent':100*(statistics.median(current['enabled'])/statistics.median(current['disabled'])-1)})
    result={mode:{'samples':len(values),'median_ns':statistics.median(values),
        'p99_ns':sorted(values)[math.ceil(.99*len(values))-1]} for mode,values in samples.items()}
    result['median_overhead_percent']=100*(result['enabled']['median_ns']/result['disabled']['median_ns']-1)
    result.update(scope='end-to-end local HTTP raw batches, same artifact/pipeline, randomized paired order; not universal throughput',
        events_per_request=32,rounds=rounds,requires_investigation=result['median_overhead_percent']>5)
    return result


def run(role):
    name = 'hec-metrics-' + uuid.uuid4().hex
    directory = runtime.ROOT / 'build/metrics' / name
    config = directory / 'config'
    config.mkdir(parents=True)
    directory.chmod(0o777)
    (config/'logstash.yml').write_text('pipeline.workers: 1\npipeline.batch.size: 1\npipeline.batch.metrics.sampling_mode: disabled\napi.enabled: true\napi.http.host: 0.0.0.0\n'
        'api.http.port: 9600\nxpack.monitoring.enabled: false\npath.data: /run-hec/data\npath.logs: /run-hec/logs\nqueue.type: memory\n')
    (config/'pipelines.yml').write_text('- pipeline.id: main\n  path.config: /run-hec/config/pipeline.conf\n')
    rules = json.dumps([{'match': 'exact', 'sourcetype': 'hec_assembly_selected', 'event_start_pattern': '^START', 'flush_timeout_ms': 600000}])
    inputs = []
    for identifier, port, extra in [('direct', 8088, 's2s_tcp_enabled => true s2s_tcp_port => 9997'),
                                     ('selected', 8089, "s2s_line_breaker_rules_json => '" + rules + "'"),
                                     ('disabled', 8090, "enable_metric => false s2s_line_breaker_rules_json => '" + rules + "'"),
                                     ('disabled_direct',8091,'enable_metric => false'),('enabled_direct',8092,'')]:
        inputs.append('splunk_hec { id => "' + identifier + '" host => "0.0.0.0" ssl_enabled => false port => ' + str(port) +
            ' state_directory => "/run-hec/state-' + identifier + '" tokens_json => \'[{"token":"' + runtime.TOKEN + '","useACK":true}]\' ' + extra + ' }')
    (config/'pipeline.conf').write_text('input { ' + '\n'.join(inputs) + ' }\n'
        'filter { ruby { code => \'while File.exist?("/run-hec/stall"); sleep 0.05; end\' } }\n'
        'output { file { path => "/run-hec/events.ndjson" codec => json_lines flush_interval => 0 } }\n')
    row = {'role': role, 'image': runtime.P['logstash.'+role+'.image'], 'status': 'fail'}
    started = False
    try:
        runtime.docker('run', '-d', '--name', name, '-p', '127.0.0.1::8088', '-p', '127.0.0.1::8089', '-p', '127.0.0.1::8090', '-p', '127.0.0.1::9600', '-p', '127.0.0.1::9997',
            '-p','127.0.0.1::8091','-p','127.0.0.1::8092','-e', 'JAVA_HOME=/usr/share/logstash/jdk', '-v', str(runtime.ROOT)+':/work:ro', '-v', str(directory)+':/run-hec',
            '--entrypoint', '/usr/share/logstash/vendor/jruby/bin/jruby', row['image'], '/work/tests/interop/install_selected_and_run.rb')
        started = True

        def ports():
            return {port: int(runtime.docker('port', name, str(port)+'/tcp').split(':')[-1]) for port in (8088, 8089, 8090, 8091, 8092, 9600, 9997)}

        exposed = ports()

        def stats():
            connection = http.client.HTTPConnection('127.0.0.1', exposed[9600], timeout=2)
            try:
                start = time.monotonic()
                connection.request('GET', '/_node/stats/pipelines/main')
                response = connection.getresponse()
                raw = response.read().decode()
                row['last_stats_response'] = {'status': response.status, 'body': raw}
                assert response.status == 200, raw
                data = json.loads(raw)
                assert time.monotonic()-start < 2, 'Node Stats deadline exceeded'
                return {item['id']: flatten(item['hec']) if 'hec' in item else None
                        for item in data['pipelines']['main']['plugins']['inputs']}
            finally:
                connection.close()

        def ready():
            try:
                if request(exposed[8088], 'health')[0] == 200:
                    observed = stats()
                    if set(observed) == {'direct', 'selected', 'disabled','disabled_direct','enabled_direct'}:
                        return observed
            except (OSError, KeyError, ValueError, AssertionError, http.client.HTTPException):
                return None

        initial = wait_for(ready, 300)
        assert initial['disabled'] is None
        for identifier in ('direct', 'selected'):
            assert set(initial[identifier]) == schema(), (identifier, set(initial[identifier]) ^ schema())
            assert all(type(value) is int for value in initial[identifier].values())
            for key, value in initial[identifier].items():
                if key.endswith('epoch_millis'):
                    assert value == -1
                elif key.startswith(('handoff.', 'assembly.flush.')) or key in ('assembly.contributions', 'store.commit.attempts'):
                    assert value == 0, (key, value)
        assert initial['selected']['assembly.enabled'] == 1 and initial['direct']['assembly.enabled'] == 0
        row['initial'] = initial

        assert request(exposed[8088], 'event', b'{"event":"one"}{"event":"two"}')[0] == 200
        assert request(exposed[8088], 'event', b'{"event":"prefix"}broken')[0] == 400
        assert request(exposed[8088], 'event', b'{}', None)[0] == 401
        assert request(exposed[8088], 'event', b'{}', 'wrong')[0] == 403
        assert request(exposed[8088], 'raw', b'one\ntwo')[0] == 200
        assert request(exposed[8088], 'ack', b'{"acks":[1]}')[0] == 200
        assert request(exposed[8088], 'unknown-private-value', b'{}')[0] == 404
        payload = body('orphan\nSTART one\ntrace\nSTART two')
        assert request(exposed[8089], 's2s', payload)[0] == 200
        assert request(exposed[8089], 's2s', payload)[0] == 200
        assert request(exposed[8090], 's2s', body('START disabled'))[0] == 200
        observed = wait_for(lambda: (s if (s := stats())['selected']['handoff.outbox.returned'] == 2 else None), 30)
        direct, selected = observed['direct'], observed['selected']
        for key, value in {'http.event.success': 1, 'http.event.invalid': 1, 'http.event.unauthorized': 1, 'http.event.forbidden': 1,
                           'http.raw.success': 1, 'http.ack.success': 1, 'http.unknown.invalid': 1,
                           'handoff.http_event.returned': 3, 'handoff.http_raw.returned': 2}.items():
            assert direct[key] == value, (key, direct[key])
        for key, value in {'assembly.contributions': 4, 'assembly.flush.new_start': 1, 'assembly.pending': 1,
                           'assembly.receipts': 1, 'store.commit.count': 3, 'http.s2s.success': 2}.items():
            assert selected[key] == value, (key, selected[key])
        assert selected['last_durable_acceptance_epoch_millis'] > 0 and selected['last_commit_epoch_millis'] > 0
        assert selected['last_handoff_epoch_millis'] > 0 and observed['disabled'] is None
        row['deltas'] = observed
        tcp_probe(exposed[9997])
        tcp=wait_for(lambda: (s if (s:=stats())['direct']['tcp.data.failure']==1 and s['direct']['tcp.connection_closed']==1 else None),30)['direct']
        for key,value in {'tcp.data.success':1,'tcp.data.failure':1,'tcp.control.success':1,'handoff.tcp.returned':2,
                          'tcp.connection_accepted':1,'tcp.connection_closed':1,'tcp.connection_failures':1}.items():assert tcp[key]==value,(key,tcp[key])
        row['tcp_deltas']=tcp

        # A stalled filter fills the real Logstash queue, blocking an input's synchronous Consumer.
        stall = directory/'stall'
        stall.write_text('block downstream')
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            blocked = executor.submit(request, exposed[8088], 'raw', b'blocked\n'*200)
            try:
                wait_for(lambda: stats()['direct']['handoff.active'] == 1, 10)
                start = time.monotonic()
                for _ in range(5):
                    assert stats()['direct']['handoff.active'] == 1
                row['blocked_scrape_seconds'] = (time.monotonic()-start)/5
                assert not blocked.done()
                # Selected orphan output is retained while its own worker is blocked behind the full queue.
                assert request(exposed[8089], 's2s', body('orphan\n'*20, source='retained-outbox'))[0] == 200
                retained = wait_for(lambda: (s if (s := stats())['selected']['assembly.outbox'] > 0 and s['selected']['handoff.active'] == 1 else None), 10)
                row['before_restart'] = retained
                runtime.docker('kill', '--signal', 'KILL', name)
            finally:
                stall.unlink(missing_ok=True)
                try:
                    blocked.result(timeout=20)
                except (OSError, http.client.HTTPException):
                    pass
        runtime.docker('start', name)
        exposed = ports()
        wait_for(ready, 600)
        after = wait_for(lambda: (s if (s := stats())['selected']['assembly.outbox'] == 0 and s['selected']['handoff.outbox.returned'] > 0 else None), 30)
        assert after['selected']['assembly.contributions'] == 0
        assert after['selected']['last_durable_acceptance_epoch_millis'] == -1
        assert after['selected']['assembly.pending'] == 1 and after['selected']['assembly.receipts'] == 2
        assert after['direct']['handoff.http_event.returned'] == 0 and after['disabled'] is None
        row.update(status='pass', after_restart=after, replay_handoffs_are_occurrences=True, disabled_absent=True,
                   schema_exact=True, integer_scalars=True, blocked_scrape_deadline_seconds=2)
        assert (directory/'.installed').read_text() == runtime.artifact_info()['sha256']
        # Otherwise identical HTTP-only inputs; assembly and TCP are disabled in both.
        row['overhead']=overhead(exposed[8092],exposed[8091])
        return row
    except BaseException as error:
        row['status']='fail'
        row['error'] = {'type': type(error).__name__, 'message': str(error)}
        raise
    finally:
        (runtime.EVIDENCE/('metrics-'+role+'.json')).write_text(json.dumps(row, indent=2)+'\n')
        if started:
            try:
                (directory/'container.log').write_text(runtime.docker('logs', name))
            finally:
                subprocess.run(['docker', 'rm', '-f', '-v', name], capture_output=True, check=True, timeout=300)


def main():
    artifact, validators = runtime.artifact_info(), runtime.validators_info()
    report = {'artifact': artifact, 'validators': validators, 'status': 'fail', 'runs': []}
    try:
        probe=runtime.ROOT/'build/metrics-probe'
        probe.mkdir(parents=True,exist_ok=True)
        classpath=str(runtime.ROOT/'build/libs'/('logstash-input-splunk_hec-'+runtime.VERSION+'.jar'))+':'+str(runtime.ROOT/'.cache/logstash-jars/*')
        subprocess.run(['javac','--release','21','-cp',classpath,'-d',str(probe),str(runtime.ROOT/'tests/interop/MetricsOverheadProbe.java')],check=True,timeout=60)
        report['isolated_handoff']=json.loads(subprocess.run(['java','-cp',str(probe)+':'+classpath,'org.logstashplugins.hec.MetricsOverheadProbe'],check=True,text=True,capture_output=True,timeout=60).stdout)
        for role in ('minimum', 'latest'):
            report['runs'].append(run(role))
            print('PASS installed Node Stats', role, flush=True)
        assert artifact == runtime.artifact_info() and validators == runtime.validators_info()
        report['status'] = 'pass'
    finally:
        (runtime.EVIDENCE/'metrics.json').write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
