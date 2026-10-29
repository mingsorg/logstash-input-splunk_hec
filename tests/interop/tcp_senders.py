#!/usr/bin/env python3
"""Real pinned UF/HF classic cooked-S2S TCP traffic directly into the plugin.

No relay, replay or fake sender is involved. Each disposable Universal/Heavy
Forwarder container monitors the same two synthetic files used by the HTTP
qualification (a five-line text file and a one-line JSON file) and connects
over classic ``tcpout`` to a real Logstash container running the packaged gem.
We then read Logstash's file output and compare it with what the forwarder was
given.

Scenarios (all against the latest pinned UF and HF, 10.6.1.1):

1. TLS on the TCP listener (``s2s_tcp_ssl_enabled => true``): sender verifies the
   certificate chain AND hostname. Matrix: compressed on/off x useACK on/off.
2. The TCP listener's DEFAULT, plaintext (the option is omitted from the pipeline
   so the real default is what gets exercised). The same matrix.
3. SIGKILL of Logstash while an ACK-enabled, compressed, TLS UF keeps running,
   then restart on the same persistent queue and TLS identity: everything written
   during the outage must still arrive, with stable event IDs.
4. ``hec_metadata`` modes ``id_only`` and ``none``: real traffic must still be
   delivered and ``@metadata`` must shrink exactly as documented, while the event
   body and the same event ID are unchanged.
5. The documented minimum Logstash (9.5.0) receives a reduced TLS set.

The HTTP listener keeps its default (TLS) throughout; this script only talks TCP.
Every Docker resource a run creates is removed in ``finally``. Evidence is written
to ``tests/interop/evidence/tcp-senders.json`` and names the gem digest it tested.
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
# Every synthetic event this test creates has a ``source`` starting with this prefix. The forwarder
# also sends its own internal logs (splunkd.log and so on); those are ignored by the checks.
SOURCE = '/tmp/hec-source.'
# What the five-line text file must turn into: one event per line, indentation kept, and the two
# identical "repeat" lines kept as TWO events (the input never deduplicates).
EXPECTED_TEXT = Counter({'alpha': 1, '  indented remains separate': 1, '重复': 1, 'repeat': 2})


def source_events(directory, host=None):
    """Synthetic-file events from Logstash's file output, optionally only those from one sender.

    Container hostnames are unique per sender, so filtering on ``host`` lets several senders
    share one Logstash receiver at the same time without their events being mixed up.
    """
    return [e for e in runtime.read_events(directory / 'events.ndjson')
            if e.get('source', '').startswith(SOURCE) and (host is None or e.get('host') == host)]


def start_sender(role, rt, receiver_host, compressed, ack, tls, network_flags):
    """Start one disposable forwarder container configured for classic ``tcpout``.

    ``role`` is ``uf`` (Universal Forwarder image) or ``hf`` (full Splunk image acting as a heavy
    forwarder). The forwarder's own configuration is written by ``sender_setup.py`` from the
    ``HEC_TCP_*`` environment variables passed here; when ``tls`` is true the receiver's public
    certificate is mounted so the sender can verify it.
    """
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
        # The sender verifies this certificate (trust + hostname). It is the one the plugin generated.
        arguments += ['-v', str(rt['directory'] / 'state/identity/server.crt') + ':/tmp/hec-server.crt:ro']
    runtime.docker(*arguments, '--entrypoint', '/usr/bin/python3', image, '/tmp/hec-sender-setup.py')
    return name, image


def wait_for(predicate, timeout, sender, description):
    """Poll ``predicate`` until it is truthy. Fails fast if the sender container dies, and always
    gives up after ``timeout`` seconds, so a hung scenario can never block the whole run forever."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        if runtime.docker('inspect', sender, '--format', '{{.State.Running}}') != 'true':
            raise RuntimeError(description + ': sender exited\n' + runtime.docker('logs', sender))
        time.sleep(1)
    raise RuntimeError(description + ': timed out\n' + runtime.docker('logs', sender)[-4000:])


def check_matrix_events(events, hostname, compressed, ack, tls, mode='full'):
    """Assert the six synthetic events arrived exactly as the forwarder read them.

    ``mode`` is the receiver's ``hec_metadata`` setting. In every mode the event BODY must be the
    same and ``@timestamp``/``@version`` must still be present; only the provenance under
    ``@metadata.splunk_hec`` may differ. (The fixture pipeline copies ``@metadata`` into a visible
    field called ``verification_metadata`` purely so the file output records it.)
    """
    assert len(events) == 6, ('expected five text + one structured source event', len(events))
    text = [e for e in events if e['source'].endswith('.log')]
    assert Counter(e['event'] for e in text) == EXPECTED_TEXT, Counter(e['event'] for e in text)
    structured = [e for e in events if e['source'].endswith('.json')]
    assert len(structured) == 1, structured
    for e in events:
        assert 'message' not in e, e                      # the input never invents a "message" field
        assert e['host'] == hostname, (e['host'], hostname)
        assert '@timestamp' in e and '@version' in e, e   # Logstash core fields are kept
    if mode == 'none':
        # No @metadata at all: the copied field is an empty map.
        assert all(e['verification_metadata'] == {} for e in events), events[0]['verification_metadata']
        return {'hec_metadata': mode}
    ids = [e['verification_metadata']['splunk_hec']['id'] for e in events]
    # The two identical "repeat" lines are different source occurrences, so their IDs must differ.
    repeated = [e['verification_metadata']['splunk_hec']['id'] for e in text if e['event'] == 'repeat']
    assert len(set(repeated)) == 2, 'distinct repeated source occurrences collapsed'
    assert len(set(ids)) == len(ids), 'event ids are not unique'
    if mode == 'id_only':
        # Only the identity, nothing else.
        assert all(set(e['verification_metadata']['splunk_hec']) == {'id'} for e in events)
        return {'hec_metadata': mode, 'ids': ids}
    for e in events:
        tcp = e['verification_metadata']['splunk_hec']['tcp']
        assert tcp['protocol'] == 's2s-v4' and tcp['compression_requested'] is compressed and tcp['ack_requested'] is ack, tcp
        # A requested compact-zlib stream must be used; latest TLS senders also compress when not requested.
        assert tcp['stream_compressed'] is True or not compressed, tcp
        assert tcp['sender_hostname'] == hostname, tcp
        assert 'event_id' in tcp, tcp
    return {'hec_metadata': mode, 'tcp_transport': events[0]['verification_metadata']['splunk_hec']['tcp'], 'ids': ids}


def run_one(role, rt, receiver_host, compressed, ack, tls, network_flags, keep=False, mode='full'):
    """One forwarder, one receiver: start the sender, wait for its data, verify, clean up.

    With ``keep=True`` the sender container is returned still running (used by the restart scenario).
    """
    sender, image = start_sender(role, rt, receiver_host, compressed, ack, tls, network_flags)
    try:
        hostname = runtime.docker('inspect', sender, '--format', '{{.Config.Hostname}}')
        # The first delivery can be slow: an emulated amd64 Splunk needs minutes to start.
        wait_for(lambda: len(source_events(rt['directory'], hostname)) >= 6, 1500, sender,
                 '%s compressed=%s ack=%s tls=%s mode=%s first delivery' % (role, compressed, ack, tls, mode))
        sender_ready(sender)
        # Observation window: if the sender were going to resend or duplicate anything, it would do so
        # now, and the exact-count check below would catch it.
        time.sleep(8)
        events = source_events(rt['directory'], hostname)
        details = check_matrix_events(events, hostname, compressed, ack, tls, mode)
        version = runtime.docker('exec', '--user', 'splunk', sender,
                                 ('/opt/splunkforwarder' if role == 'uf' else '/opt/splunk') + '/bin/splunk', 'version')
        result = {'role': role, 'image': image, 'version': version, 'compressed': compressed, 'useACK': ack,
                  'tls_verified_hostname_and_trust': tls, 'source_event_count': len(events),
                  'sender_hostname': hostname, **details}
        print('PASS', role, 'compressed=%s ack=%s tls=%s mode=%s' % (compressed, ack, tls, mode), flush=True)
        return (result, sender) if keep else result
    except BaseException:
        if keep:
            subprocess.run(['docker', 'rm', '-f', '-v', sender], capture_output=True, timeout=60)
        raise
    finally:
        if not keep:
            subprocess.run(['docker', 'rm', '-f', '-v', sender], capture_output=True, timeout=60)


def restart_scenario(role, rt, receiver_host, network_flags):
    """Hard-kill the receiver while a real ACK sender is connected, then bring it back.

    The forwarder keeps running the whole time. Lines appended to its monitored file while the
    receiver is dead must arrive after the restart (the forwarder holds unacknowledged data and
    retries), each with a stable event ID, and the TLS identity must be reused, not regenerated.
    """
    result, sender = run_one(role, rt, receiver_host, True, True, True, network_flags, keep=True)
    host = result['sender_hostname']
    try:
        certificate = (rt['directory'] / 'state/identity/server.crt').read_bytes()
        runtime.docker('kill', '--signal', 'KILL', rt['name'])     # no graceful shutdown on purpose
        appended = ['outage-%d-%s' % (i, uuid.uuid4().hex[:6]) for i in range(1, 4)]
        runtime.docker('exec', '--user', 'root', sender, 'sh', '-c',
                       "printf '%s\\n' " + ' '.join(appended) + " >> /tmp/hec-source.log")
        time.sleep(15)  # the real sender must keep these bytes while the receiver is dead
        runtime.docker('start', rt['name'])
        runtime.ready(rt['name'], rt['directory'])
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
            # At-least-once delivery may duplicate, but a resend must carry the same ID.
            assert len(by_event[value]) == 1, ('unstable ID across resend', value, by_event[value])
        result.update({'restart': {'receiver_killed_with_sigkill': True, 'appended_while_down': len(appended),
                                   'all_delivered_after_restart': True, 'certificate_reused': True,
                                   'duplicates_possible_ids_stable': True,
                                   'delivery_counts': {v: sum(e['event'] == v for e in events) for v in appended}}})
        return result
    finally:
        subprocess.run(['docker', 'rm', '-f', '-v', sender], capture_output=True, timeout=60)


# The plugin deliberately warns once at startup when a listener runs without TLS. That is expected
# behaviour (and asserted below), not a connection problem.
PLAINTEXT_STARTUP_WARNING = 'S2S TCP listener is plaintext'


def receiver_log_warnings(rt):
    """Plugin warnings/errors from the receiver's log, EXCLUDING the intentional plaintext startup
    warning. A clean run has none: a warning here means a connection was closed without being served
    (for example an event above the size cap)."""
    logs = runtime.docker('logs', rt['name'], timeout=120)
    return [line for line in logs.splitlines()
            if ('S2S TCP' in line or 'ERROR' in line) and PLAINTEXT_STARTUP_WARNING not in line]


def plaintext_warning_logged(rt):
    """True when the receiver logged the startup warning about the plaintext TCP listener."""
    return PLAINTEXT_STARTUP_WARNING in runtime.docker('logs', rt['name'], timeout=120)


def main():
    network_flags, receiver_host = sender_network()
    roles = os.environ.get('HEC_TCP_ROLES', 'uf,hf').split(',')
    report = {'matrix': [], 'status': 'fail'}
    runtimes = []
    try:
        # --- Scenarios 1-3: TLS and default-plaintext matrix ---------------------------------------------
        for tls in (True, False):
            rt = runtime.start_tcp_runtime('latest', tls=tls)
            runtimes.append(rt)
            report.setdefault('artifact', rt['artifact'])
            report['startup_mode'] = os.environ.get('HEC_STARTUP_MODE', 'direct')
            label = 'tls' if tls else 'plaintext'

            def role_matrix(role, rt=rt, tls=tls):
                return [run_one(role, rt, receiver_host, compressed, ack, tls, network_flags)
                        for compressed in (False, True) for ack in (True, False)]
            # One UF and one HF run concurrently against the same receiver; hostnames keep them apart.
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(roles)) as pool:
                for rows in pool.map(role_matrix, roles):
                    report['matrix'].extend(rows)
            if tls:
                report['restart'] = restart_scenario('uf', rt, receiver_host, network_flags)
            report.setdefault('receiver_warnings', {})[label] = receiver_log_warnings(rt)
            # The default (plaintext) listener must announce itself; the TLS listener must not.
            assert plaintext_warning_logged(rt) is (not tls), ('plaintext startup warning mismatch', label)
            report.setdefault('plaintext_startup_warning_logged', {})[label] = plaintext_warning_logged(rt)
            # A real heavy forwarder's >1 MiB internal record must not be refused (it would wedge the
            # sender's queue), and ordinary disconnects are not diagnostics.
            assert not report['receiver_warnings'][label], report['receiver_warnings']
            report.setdefault('largest_event_line_bytes', {})[label] = max(
                (len(line) for line in (rt['directory'] / 'events.ndjson').read_bytes().split(b'\n')), default=0)
            subprocess.run(['docker', 'rm', '-f', '-v', rt['name']], capture_output=True, timeout=60)
            runtimes.remove(rt)

        # --- Scenario 4: hec_metadata modes with real traffic -------------------------------------------
        report['hec_metadata_modes'] = {}
        for mode in ('id_only', 'none'):
            rt = runtime.start_tcp_runtime('latest', tls=False, hec_metadata=mode)
            runtimes.append(rt)
            report['hec_metadata_modes'][mode] = run_one('uf', rt, receiver_host, False, True, False, network_flags, mode=mode)
            assert not receiver_log_warnings(rt)
            subprocess.run(['docker', 'rm', '-f', '-v', rt['name']], capture_output=True, timeout=60)
            runtimes.remove(rt)

        # --- Scenario 5: the documented minimum Logstash also receives real TCP traffic -------------------
        rt = runtime.start_tcp_runtime('minimum', tls=True)
        runtimes.append(rt)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            runs = list(pool.map(lambda a: run_one(a[0], rt, receiver_host, a[1], True, True, network_flags),
                                 [('uf', True), ('hf', False)]))
        report['minimum_logstash'] = {'image': runtime.P['logstash.minimum.image'],
                                      'version': runtime.P['logstash.minimum'], 'runs': runs}
        assert not receiver_log_warnings(rt)
        subprocess.run(['docker', 'rm', '-f', '-v', rt['name']], capture_output=True, timeout=60)
        runtimes.remove(rt)

        # The gem must not have changed while the run was in progress, or the evidence would not
        # describe the artifact it names.
        assert runtime.artifact_info() == report['artifact'], 'artifact changed during qualification'
        report['status'] = 'pass'
        report['scope'] = ('real UF/HF classic cooked TCP to the plugin: verified TLS and default plaintext, '
                           'compression and useACK matrix, receiver SIGKILL/resume, hec_metadata modes')
        print('PASS tcp qualification', len(report['matrix']), 'sender runs', flush=True)
    finally:
        # Evidence is always written (status "fail" if anything above raised) and containers always removed.
        (EVIDENCE / 'tcp-senders.json').write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
        for rt in runtimes:
            subprocess.run(['docker', 'rm', '-f', '-v', rt['name']], capture_output=True, timeout=60)
    return 0 if report['status'] == 'pass' else 1


if __name__ == '__main__':
    sys.exit(main())
