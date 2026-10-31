#!/usr/bin/env python3
"""Read-only validation of the running test lab: UF-host attribution, route markers and current traffic."""
import argparse
import base64
import json
import math
import os
from pathlib import Path
import signal
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import lab


def complete_evidence(result, max_age):
    positive = [row for row in result if int(row['count']) > 0]
    seen = {row['index'] for row in positive}

    def fresh(row):
        return (math.isfinite(float(row['age_seconds']))
                and -60 <= float(row['age_seconds']) <= max_age)

    fresh_internal = any(row['index'] == '_internal' and fresh(row) for row in positive)
    fresh_sources = all(any(row['index'] == 'hec_demo' and row['source'] == source
                            and row['sourcetype'] == sourcetype and fresh(row) for row in positive)
                        for source, sourcetype in (('/tmp/hec-chain.log', 'hec_chain_text'),
                                                   ('/tmp/hec-chain.json', 'hec_chain_json')))
    return {'_internal', '_audit', 'hec_demo'} <= seen and fresh_internal and fresh_sources


def options():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', help='existing directory containing connection.json; discovered from Docker by default')
    parser.add_argument('--timeout', type=int, default=180, help='finite observation budget in seconds')
    parser.add_argument('--max-age', type=int, default=900, help='maximum indexed age for application and internal traffic')
    parser.add_argument('--output', default=str(lab.LAB / 'reports/validation.json'), help='local report path; keep generated reports out of Git')
    args = parser.parse_args()
    if args.timeout <= 0 or args.max_age <= 0:
        parser.error('--timeout and --max-age must be positive')
    try:
        args.output = str(lab.report_path(args.output))
    except (OSError, ValueError, AttributeError) as failure:
        parser.error(str(failure))
    return args


def validate(args):
    report = {'status': 'fail', 'mode': 'read-only existing-lab verification',
              'required_indexes': ['_internal', '_audit', 'hec_demo'],
              'max_age_seconds': args.max_age}
    deadline = time.monotonic() + args.timeout
    try:
        rows = lab.inspect()
        if any(not row['State']['Running'] or row['State'].get('Restarting') for row in rows.values()):
            raise RuntimeError('all three existing lab containers must be running without restarting')
        state, secret = lab.credentials(rows, args.state_dir)
        indexer, logstash, uf = (rows[name] for name in lab.NAMES)
        host = uf['Config']['Hostname']
        # Quote only a plain Docker hostname in SPL; do not accept injected search text.
        if not host or any(not (char.isalnum() or char in '.-_') for char in host):
            raise RuntimeError('unsupported UF hostname')
        report['forwarder_host'] = host
        search = ('search (index=* OR index=_*) earliest=0 host="' + host +
                  '" ingest_via::logstash logstash_pipeline::uf_hec_s2s_to_splunk'
                  ' | stats count max(_indextime) AS latest_index_time by index source sourcetype ingest_via logstash_pipeline'
                  ' | eval age_seconds=now()-latest_index_time')
        report['search'] = search
        auth = 'Basic ' + base64.b64encode((secret['username'] + ':' + secret['password']).encode()).decode()
        url = 'https://localhost:' + str(lab.port(indexer, 8089)) + '/services/search/jobs/export'
        # The live management API uses Splunk's vendor-generated certificate.
        # This exception is diagnostic only; both data-plane hops verify trust/name.
        context = ssl._create_unverified_context()

        def query(text):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('validation observation deadline exceeded')
            request = urllib.request.Request(url,
                data=urllib.parse.urlencode({'search': text, 'output_mode': 'json'}).encode(),
                headers={'Authorization': auth})
            with urllib.request.urlopen(request, context=context, timeout=min(30, remaining)) as response:
                result = []
                for line in response:
                    if time.monotonic() > deadline:
                        raise TimeoutError('search response exceeded observation deadline')
                    record = json.loads(line)
                    errors = [message for message in record.get('messages', []) if message.get('type') in ('ERROR', 'FATAL')]
                    if errors:
                        raise RuntimeError('Splunk search returned errors: ' + str(errors))
                    if 'result' in record:
                        result.append(record['result'])
                return result

        while True:
            result = query(search)
            report['tagged_indexer_results'] = result
            if complete_evidence(result, args.max_age):
                break
            if time.monotonic() + 5 >= deadline:
                raise RuntimeError('missing tagged indexes or stale/missing internal, text or JSON traffic; see report')
            time.sleep(5)

        sample = query('search index=_internal earliest=0 host="' + host +
            '" ingest_via::logstash logstash_pipeline::uf_hec_s2s_to_splunk'
            ' | head 1 | table host source sourcetype ingest_via logstash_pipeline _raw')
        if not sample:
            raise RuntimeError('no route-tagged internal sample')
        report['tagged_internal_sample'] = sample[0]
        matched = False
        # Search recent complete records without rescanning an unrotated file
        # from its beginning. A partial final line is ignored by reverse_lines.
        for line in lab.reverse_lines(state / 'logstash/received.ndjson'):
            if time.monotonic() > deadline:
                raise TimeoutError('local trace comparison exceeded observation deadline')
            event = json.loads(line)
            fields = event.get('fields', {})
            if (event.get('index') == '_internal' and event.get('host') == host
                    and fields.get('ingest_via') == 'logstash'
                    and fields.get('logstash_pipeline') == 'uf_hec_s2s_to_splunk'
                    and event.get('source') == sample[0].get('source')
                    and event.get('event') == sample[0].get('_raw')):
                matched = True
                break
        if not matched:
            raise RuntimeError('indexed internal raw sample not found in the last 64 MiB of the local Logstash trace')
        report.update({'status': 'pass', 'raw_sample_matches_logstash': True,
                       'scope': 'Existing lab only; audit presence plus internal/text/JSON freshness required; no events injected.'})
    except Exception as failure:
        report['error_type'] = type(failure).__name__
        report['error'] = str(failure)
    try:
        lab.save_report(args.output, report)
    except OSError as failure:
        print('Could not save validation report: ' + str(failure), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report['status'] == 'pass' else 1


def main():
    args = options()
    if os.environ.get('_TEST_LAB_VALIDATE_WORKER') == '1':
        return validate(args)
    # A parent deadline covers blocking Docker/API reads as well as Python
    # iteration. A socket inactivity timeout alone is not a total wall clock cap.
    environment = dict(os.environ, _TEST_LAB_VALIDATE_WORKER='1')
    child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]],
        env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        start_new_session=(os.name == 'posix'))
    try:
        stdout, stderr = child.communicate(timeout=args.timeout)
    except subprocess.TimeoutExpired:
        if os.name == 'posix':
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            child.kill()
        child.communicate()
        report = {'status': 'fail', 'mode': 'read-only existing-lab verification',
                  'error_type': 'TimeoutError', 'error': 'total validation deadline exceeded',
                  'timeout_seconds': args.timeout, 'max_age_seconds': args.max_age}
        lab.save_report(args.output, report)
        print(json.dumps(report, indent=2))
        return 1
    if stdout:
        print(stdout, end='')
    if stderr:
        print(stderr, end='', file=sys.stderr)
    return child.returncode


if __name__ == '__main__':
    sys.exit(main())
