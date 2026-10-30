#!/usr/bin/env python3
"""Narrow final-gem qualification: real UF/HF per-record metadata over HTTPS/TCP.

Run minimum/none and latest/full,id_only,none on persisted queues. Exact native
payloads, indexed values and selected wire metadata are checked in every case.
Full mode additionally compares the selected values against decoded provenance.
Every owned container is removed and failures are recorded against the gem digest.
"""
import json
import sys
import time
import uuid

import runtime
import tcp_senders
from senders import sender_bootstrap_args, sender_network, sender_ready

MAPPING = {'_path': 'path', 'crcSalt': 'salt', '_MetaData:Index': 'host',
           'not_present': 'omitted', 'sender_hostname': 'not_handshake',
           'message': 'not_indexed'}


def check_native(events, hostname, mode):
    # Shared source assertions work for either transport; TCP-only assertions
    # live in tcp_senders.check_matrix_events. No payload timestamp parsing by the input.
    from collections import Counter
    assert len(events) == 6, len(events)
    text = [e for e in events if e['source'].endswith('.log')]
    assert Counter(e['event'] for e in text) == tcp_senders.EXPECTED_TEXT
    structured = [e for e in events if e['source'].endswith('.json')]
    assert len(structured) == 1
    for event in events:
        assert event['host'] == hostname and event['index'] == 'main'
        assert '@timestamp' in event and event['@version'] == '1' and 'message' not in event
        assert event['sourcetype'] == ('hec_native_text' if event['source'].endswith('.log') else 'hec_native_json')
        if mode == 'none':
            assert event['verification_metadata'] == {}
        else:
            provenance = event['verification_metadata']['splunk_hec']
            assert provenance['id'].startswith('s2s-v1:')
            if mode == 'id_only': assert set(provenance) == {'id'}
    event = structured[0]
    raw = '{"time":"1790000000.123456789","message":"native","a.b":["first","second"],"host":"payload-host"}'
    # Forwarders can retain the terminating LF on structured records; both are native.
    assert event['event'] in (raw, raw + '\n'), event
    # Splunk's indexed JSON array name includes its native {} suffix. Preserve
    # the wire name instead of assuming the payload's JSON property spelling.
    assert event['fields'] == {'host': 'payload-host', 'message': 'native',
                               'time': '1790000000.123456789', 'a.b{}': ['first', 'second']}, event
    assert event['time'] == '1790000000.123456', event
    assert event['@timestamp'] == '2026-09-21T14:13:20.123456Z', event


def error_details(failure):
    return {'type': type(failure).__name__, 'message': str(failure) or repr(failure)}


def remove_container(identity, record):
    """Cleanup failures are evidence, never a passing scenario or a lost report."""
    try:
        runtime.docker('rm', '-f', '-v', identity, timeout=60)
        return True
    except Exception as failure:
        record.setdefault('cleanup_errors', []).append({'container': identity, **error_details(failure)})
        return False


def cleanup_sender(identity, ownership, row):
    # A create timeout may happen AFTER Docker creates the container. Query only
    # this run's unique label; a reused name must never authorize removal.
    if identity is not None:
        return remove_container(identity, row)
    try:
        identities = runtime.docker('ps', '-aq', '--filter', 'label=' + ownership).split()
    except Exception as failure:
        row.setdefault('cleanup_errors', []).append(error_details(failure))
        return False
    results = [remove_container(identity, row) for identity in identities]
    return all(results)


def run_sender(role, transport, rt, receiver_host, flags, mode, row):
    image = runtime.P['uf.image' if role == 'uf' else 'splunk.image']
    sender = 'hec-meta-' + transport + '-' + role + '-' + uuid.uuid4().hex[:8]
    ownership = 'org.logstash.hec.metadata-run=' + uuid.uuid4().hex
    identity = None
    row.update({'image': image, 'sender_ownership_label': ownership})
    try:
        arguments = ['create', '--name', sender, '--label', ownership,
            '--platform', 'linux/amd64', '--user', 'root', *sender_bootstrap_args(sender), *flags,
            '-e', 'SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com',
            '-v', str(runtime.ROOT/'tests/interop/sender_setup.py') + ':/tmp/hec-sender-setup.py:ro',
            '-v', str(rt['directory']/'state/identity/server.crt') + ':/tmp/hec-server.crt:ro']
        if transport == 'tcp':
            arguments += ['-e', 'HEC_TRANSPORT=tcp',
                '-e', 'HEC_TCP_RECEIVER=%s:%d' % (receiver_host, rt['tcp_port']),
                '-e', 'HEC_TCP_COMPRESSED=true', '-e', 'HEC_TCP_ACK=true', '-e', 'HEC_TCP_TLS=true']
        else:
            arguments += ['-e', 'HEC_RECEIVER_URI=https://' + receiver_host + ':' + str(rt['port'])]
        identity = runtime.docker(*arguments, '--entrypoint', '/usr/bin/python3', image, '/tmp/hec-sender-setup.py')
        row['sender_container'] = identity
        runtime.docker('start', identity)
        host = runtime.docker('inspect', identity, '--format', '{{.Config.Hostname}}')
        tcp_senders.wait_for(lambda: len(tcp_senders.source_events(rt['directory'], host)) >= 6,
                             1500, identity, role + '/' + transport + '/' + mode)
        sender_ready(identity)
        time.sleep(8)
        events = tcp_senders.source_events(rt['directory'], host)
        check_native(events, host, mode)
        if transport == 'tcp':
            tcp_senders.check_matrix_events(events, host, True, True, True, mode)
        tcp_senders.check_selected_metadata(events, MAPPING, mode)
        home = '/opt/splunkforwarder' if role == 'uf' else '/opt/splunk'
        version = runtime.docker('exec', '--user', 'splunk', identity, home + '/bin/splunk', 'version')
        row.update({'version': version, 'source_events': events})
    except Exception as failure:
        row['error'] = error_details(failure)
        raise
    finally:
        if not cleanup_sender(identity, ownership, row):
            row['status'] = 'fail'
            if sys.exc_info()[0] is None:
                raise RuntimeError('sender cleanup failed; see scenario cleanup_errors')
    row['status'] = 'pass'


def finish_receiver(rt, report, diagnostics=False):
    """Keep log collection independent of cleanup and unconditional report writing."""
    if diagnostics:
        try:
            report['receiver_logs'] = runtime.docker('logs', rt['name'])
        except Exception as failure:
            report.setdefault('diagnostic_errors', []).append(error_details(failure))
    return remove_container(rt['name'], report)


def main():
    report = {'artifact': runtime.artifact_info(), 'mapping': MAPPING, 'runs': [], 'status': 'fail'}
    rt = None
    completed = False
    try:
        flags, host = sender_network()
        for runtime_role, mode in [('minimum', 'none'), ('latest', 'full'), ('latest', 'id_only'), ('latest', 'none')]:
            rt = runtime.start_tcp_runtime(runtime_role, tls=True, hec_metadata=mode, s2s_metadata_fields=MAPPING)
            assert rt['artifact'] == report['artifact']
            for transport in ('http', 'tcp'):
                for role in ('uf', 'hf'):
                    # Retain identity even if launch or a bare assertion fails.
                    row = {'role': role, 'transport': transport, 'hec_metadata': mode,
                           'runtime_role': runtime_role, 'logstash': runtime.P['logstash.' + runtime_role],
                           'receiver_image': runtime.P['logstash.' + runtime_role + '.image'],
                           'queue': 'persisted', 'status': 'fail'}
                    report['runs'].append(row)
                    run_sender(role, transport, rt, host, flags, mode, row)
                    print('PASS', runtime_role, mode, transport, role, flush=True)
            warnings = tcp_senders.receiver_log_warnings(rt)
            assert not warnings, warnings
            if not finish_receiver(rt, report):
                raise RuntimeError('receiver cleanup failed; see cleanup_errors')
            rt = None
        assert runtime.artifact_info() == report['artifact'], 'artifact changed during qualification'
        completed = True
    except Exception as failure:
        report['error'] = error_details(failure)
    finally:
        if rt is not None:
            finish_receiver(rt, report, diagnostics=True)
        if completed and not report.get('cleanup_errors'):
            report['status'] = 'pass'
        (runtime.ROOT/'tests/interop/evidence/metadata-fields.json').write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + '\n')
    return 0 if report['status'] == 'pass' else 1


if __name__ == '__main__':
    sys.exit(main())
