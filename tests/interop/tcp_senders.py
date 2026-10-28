#!/usr/bin/env python3
"""Real pinned UF/HF classic cooked-S2S TCP traffic directly into the plugin.

No relay, replay or fake sender is involved: each disposable UF/HF container
monitors the same synthetic files used by the HTTP qualification and connects
to the Logstash fixture over classic TCP. Matrix:

* UF and HF, compressed on/off, useACK on/off, verified TLS (hostname checked);
* the same UF/HF modes with explicit test-only plaintext TCP;
* a SIGKILL of Logstash while an ACK-enabled compressed TLS UF stays running,
  followed by restart on the same persistent queue/identity.

Every Docker resource created by a run is removed in ``finally``.
"""
import concurrent.futures
import json
import os
import subprocess
import sys
import time
import uuid
from collections import Counter

import runtime
from senders import sender_bootstrap_args, sender_network, sender_ready

ROOT = runtime.ROOT
EVIDENCE = ROOT / 'tests/interop/evidence'
SOURCE = '/tmp/hec-source.'
EXPECTED_TEXT = Counter({'alpha': 1, '  indented remains separate': 1, '重复': 1, 'repeat': 2})


def source_events(directory, host=None):
    """Synthetic-file events, optionally only those from one sender (container hostnames are unique)."""
    return [e for e in runtime.read_events(directory / 'events.ndjson')
            if e.get('source', '').startswith(SOURCE) and (host is None or e.get('host') == host)]


def start_sender(role, rt, receiver_host, compressed, ack, tls, network_flags):
    image = runtime.P['uf.image' if role == 'uf' else 'splunk.image']
    name = 'hec-tcp-sender-%s-%s' % (role, uuid.uuid4().hex[:8])
    arguments = ['run', '-d', '--name', name, '--platform', 'linux/amd64', '--user', 'root',
                 *sender_bootstrap_args(name), *network_flags,
                 '-e', 'SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com',
                 '-e', 'HEC_TRANSPORT=tcp', '-e', 'HEC_TCP_RECEIVER=%s:%d' % (receiver_host, rt['tcp_port']),
                 '-e', 'HEC_TCP_COMPRESSED=' + str(compressed).lower(), '-e', 'HEC_TCP_ACK=' + str(ack).lower(),
                 '-e', 'HEC_TCP_TLS=' + str(tls).lower(),
                 '-v', str(ROOT / 'tests/interop/sender_setup.py') + ':/tmp/hec-sender-setup.py:ro']
    if tls:
        arguments += ['-v', str(rt['directory'] / 'state/identity/server.crt') + ':/tmp/hec-server.crt:ro']
    runtime.docker(*arguments, '--entrypoint', '/usr/bin/python3', image, '/tmp/hec-sender-setup.py')
    return name, image


def wait_for(predicate, timeout, sender, description):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        if runtime.docker('inspect', sender, '--format', '{{.State.Running}}') != 'true':
            raise RuntimeError(description + ': sender exited\n' + runtime.docker('logs', sender))
        time.sleep(1)
    raise RuntimeError(description + ': timed out\n' + runtime.docker('logs', sender)[-4000:])


def check_matrix_events(events, hostname, compressed, ack, tls):
    assert len(events) == 6, ('expected five text + one structured source event', len(events))
    text = [e for e in events if e['source'].endswith('.log')]
    assert Counter(e['event'] for e in text) == EXPECTED_TEXT, Counter(e['event'] for e in text)
    repeated = [e['verification_metadata']['splunk_hec']['id'] for e in text if e['event'] == 'repeat']
    assert len(set(repeated)) == 2, 'distinct repeated source occurrences collapsed'
    structured = [e for e in events if e['source'].endswith('.json')]
    assert len(structured) == 1, structured
    for e in events:
        assert 'message' not in e, e
        assert e['host'] == hostname, (e['host'], hostname)
        tcp = e['verification_metadata']['splunk_hec']['tcp']
        assert tcp['protocol'] == 's2s-v4' and tcp['compression_requested'] is compressed and tcp['ack_requested'] is ack, tcp
        # A requested compact-zlib stream must be used; latest TLS senders may also compress when not requested.
        assert tcp['stream_compressed'] is True or not compressed, tcp
        assert tcp['sender_hostname'] == hostname, tcp
        assert 'event_id' in tcp, tcp
    return {'tcp_transport': events[0]['verification_metadata']['splunk_hec']['tcp']}


def run_one(role, rt, receiver_host, compressed, ack, tls, network_flags, keep=False):
    sender, image = start_sender(role, rt, receiver_host, compressed, ack, tls, network_flags)
    try:
        hostname = runtime.docker('inspect', sender, '--format', '{{.Config.Hostname}}')
        wait_for(lambda: len(source_events(rt['directory'], hostname)) >= 6, 1500, sender,
                 '%s compressed=%s ack=%s tls=%s first delivery' % (role, compressed, ack, tls))
        sender_ready(sender)
        time.sleep(8)  # retransmission/duplicate observation window; no cap is imposed on correctness
        events = source_events(rt['directory'], hostname)
        details = check_matrix_events(events, hostname, compressed, ack, tls)
        version = runtime.docker('exec', '--user', 'splunk', sender,
                                 ('/opt/splunkforwarder' if role == 'uf' else '/opt/splunk') + '/bin/splunk', 'version')
        result = {'role': role, 'image': image, 'version': version, 'compressed': compressed, 'useACK': ack,
                  'tls_verified_hostname_and_trust': tls, 'source_event_count': len(events),
                  'sender_hostname': hostname, **details}
        print('PASS', role, 'compressed=%s ack=%s tls=%s' % (compressed, ack, tls), flush=True)
        return (result, sender) if keep else result
    except BaseException:
        if keep:
            subprocess.run(['docker', 'rm', '-f', '-v', sender], capture_output=True, timeout=60)
        raise
    finally:
        if not keep:
            subprocess.run(['docker', 'rm', '-f', '-v', sender], capture_output=True, timeout=60)


def restart_scenario(role, rt, receiver_host, network_flags):
    """Hard-kill the receiver while a real ACK sender is connected, then resume."""
    result, sender = run_one(role, rt, receiver_host, True, True, True, network_flags, keep=True)
    host = result['sender_hostname']
    try:
        certificate = (rt['directory'] / 'state/identity/server.crt').read_bytes()
        runtime.docker('kill', '--signal', 'KILL', rt['name'])
        appended = ['outage-%d-%s' % (i, uuid.uuid4().hex[:6]) for i in range(1, 4)]
        runtime.docker('exec', '--user', 'root', sender, 'sh', '-c',
                       "printf '%s\\n' " + ' '.join(appended) + " >> /tmp/hec-source.log")
        time.sleep(15)  # the real sender must keep these bytes while the receiver is dead
        runtime.docker('start', rt['name'])
        port, _ = runtime.ready(rt['name'], rt['directory'])
        assert (rt['directory'] / 'state/identity/server.crt').read_bytes() == certificate, 'TLS identity changed'

        def seen():
            texts = Counter(e['event'] for e in source_events(rt['directory'], host))
            return all(texts[v] >= 1 for v in appended)
        wait_for(seen, 300, sender, 'events appended during receiver outage')
        events = source_events(rt['directory'], host)
        assert sum(e['event'] in EXPECTED_TEXT for e in events) >= 5, 'pre-kill source events were lost'
        by_event = {}
        for e in events:
            by_event.setdefault(e['event'], set()).add(e['verification_metadata']['splunk_hec']['id'])
        for value in appended:
            assert len(by_event[value]) == 1, ('unstable ID across resend', value, by_event[value])
        result.update({'restart': {'receiver_killed_with_sigkill': True, 'appended_while_down': len(appended),
                                   'all_delivered_after_restart': True, 'certificate_reused': True,
                                   'duplicates_possible_ids_stable': True,
                                   'delivery_counts': {v: sum(e['event'] == v for e in events) for v in appended}}})
        return result
    finally:
        subprocess.run(['docker', 'rm', '-f', '-v', sender], capture_output=True, timeout=60)


def main():
    network_flags, receiver_host = sender_network()
    roles = os.environ.get('HEC_TCP_ROLES', 'uf,hf').split(',')
    report = {'matrix': [], 'status': 'fail'}
    runtimes = []
    try:
        for tls in (True, False):
            rt = runtime.start_tcp_runtime('latest', tls=tls)
            runtimes.append(rt)
            report.setdefault('artifact', rt['artifact'])
            report['startup_mode'] = os.environ.get('HEC_STARTUP_MODE', 'direct')
            def role_matrix(role, rt=rt, tls=tls):
                return [run_one(role, rt, receiver_host, compressed, ack, tls, network_flags)
                        for compressed in (False, True) for ack in (True, False)]
            # One UF and one HF sender run concurrently; each is identified by its unique hostname.
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(roles)) as pool:
                for rows in pool.map(role_matrix, roles):
                    report['matrix'].extend(rows)
            if tls:
                report['restart'] = restart_scenario('uf', rt, receiver_host, network_flags)
            logs = runtime.docker('logs', rt['name'], timeout=120)
            report.setdefault('receiver_warnings', {})['tls' if tls else 'plaintext'] = [
                line for line in logs.splitlines() if 'S2S TCP' in line or 'ERROR' in line]
            # A real heavy forwarder's >1 MiB internal record must not be refused (it would
            # wedge the sender's queue), and ordinary disconnects are not diagnostics.
            assert not report['receiver_warnings']['tls' if tls else 'plaintext'], report['receiver_warnings']
            report.setdefault('largest_event_line_bytes', {})['tls' if tls else 'plaintext'] = max(
                (len(line) for line in (rt['directory'] / 'events.ndjson').read_bytes().split(b'\n')), default=0)
            subprocess.run(['docker', 'rm', '-f', '-v', rt['name']], capture_output=True, timeout=60)
            runtimes.remove(rt)
        # The documented minimum Logstash also receives real TCP traffic (reduced matrix).
        rt = runtime.start_tcp_runtime('minimum', tls=True)
        runtimes.append(rt)
        report['minimum_logstash'] = {'image': runtime.P['logstash.minimum.image'], 'version': runtime.P['logstash.minimum'],
            'runs': list(concurrent.futures.ThreadPoolExecutor(max_workers=2).map(
                lambda a: run_one(a[0], rt, receiver_host, a[1], True, True, network_flags), [('uf', True), ('hf', False)]))}
        minimum_warnings = [line for line in runtime.docker('logs', rt['name'], timeout=120).splitlines()
                            if 'S2S TCP' in line or 'ERROR' in line]
        assert not minimum_warnings, minimum_warnings
        subprocess.run(['docker', 'rm', '-f', '-v', rt['name']], capture_output=True, timeout=60)
        runtimes.remove(rt)
        assert runtime.artifact_info() == report['artifact'], 'artifact changed during qualification'
        report['status'] = 'pass'
        report['scope'] = ('real UF/HF classic cooked TCP to the plugin: verified TLS and test-only plaintext, '
                           'compression and useACK matrix, receiver SIGKILL/resume')
        print('PASS tcp qualification', len(report['matrix']), 'sender runs', flush=True)
    finally:
        (EVIDENCE / 'tcp-senders.json').write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
        for rt in runtimes:
            subprocess.run(['docker', 'rm', '-f', '-v', rt['name']], capture_output=True, timeout=60)
    return 0 if report['status'] == 'pass' else 1


if __name__ == '__main__':
    sys.exit(main())
