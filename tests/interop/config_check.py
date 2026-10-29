#!/usr/bin/env python3
"""Validate every `splunk_hec` configuration snippet in docs/configuration.md with
the packaged gem in the pinned minimum and latest Logstash images (`logstash -t`),
plus negative cases whose documented startup errors must occur.

Fragments are extracted from the document, not copied here, so the document cannot
drift from the plugin. Material files referenced by snippets are generated in the
disposable container. Nothing is started as a service; `-t` constructs each plugin.
"""
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

import runtime

ROOT = runtime.ROOT
DOC = (ROOT / 'docs/configuration.md').read_text()

BLOCKS = [b for b in re.findall(r'```logstash\n(.*?)```', DOC, re.S) if 'splunk_hec' in b]
# Complete example pipelines shipped in examples/ are validated too, so they cannot rot either.
EXAMPLES = [f.read_text() for f in sorted((ROOT / 'examples').glob('*.conf')) if re.search(r'^\s*splunk_hec\s*{', f.read_text(), re.M)]
SUBSTITUTIONS = [
    ('/var/lib/logstash/', '/tmp/state/'),
    ('/etc/logstash/hec-inputs.conf', '/tmp/files/hec-inputs.conf'),
    ('/etc/logstash/hec.p12', '/tmp/files/hec.p12'),
    ('/etc/logstash/hec.crt', '/tmp/files/hec.crt'),
    ('/etc/logstash/hec.pkcs8.key', '/tmp/files/hec.pkcs8.key'),
    ('/etc/logstash/clients-ca.pem', '/tmp/files/clients-ca.pem'),
]

def prepare(block):
    for old, new in SUBSTITUTIONS:
        block = block.replace(old, new)
    if re.search(r'^\s*output\s*{', block, re.M):
        return block           # an example that is already a complete pipeline
    if not re.search(r'^\s*input\s*{', block, re.M):
        block = 'input {\n' + block + '\n}\n'
    # Examples use different state paths per input already; make each snippet independent.
    return block + '\noutput { stdout { } }\n'

NEGATIVE = {
    'unknown option': ('splunk_hec { state_directory => "/tmp/n1" nonsense => 1 }', "Unknown setting 'nonsense'"),
    'codec rejected': ('splunk_hec { state_directory => "/tmp/n2" codec => "json" }', "Unknown setting 'codec'"),
    'tcp port equals http': ('splunk_hec { state_directory => "/tmp/n3" port => 9000 s2s_tcp_enabled => true s2s_tcp_port => 9000 }', 'S2S TCP port must be distinct'),
    'inconsistent limits': ('splunk_hec { state_directory => "/tmp/n4" max_connections => 1 max_concurrent_requests => 16 }', 'inconsistent positive resource limits'),
    # Certificate material is shared, so it is only an error when NO listener uses TLS.
    'tls material with all tls off': ('splunk_hec { state_directory => "/tmp/n5" ssl_enabled => false ssl_keystore => "/tmp/files/hec.p12" ssl_keystore_password => "changeit" }', 'TLS material requires TLS enabled'),
    # Client-certificate authentication needs TLS on THAT listener.
    'http client auth without http tls': ('splunk_hec { state_directory => "/tmp/n5b" ssl_enabled => false ssl_client_authentication => true }', 'ssl_client_authentication requires ssl_enabled'),
    'tcp client auth without tcp tls': ('splunk_hec { state_directory => "/tmp/n5c" s2s_tcp_enabled => true s2s_tcp_ssl_client_authentication => true }', 's2s_tcp_ssl_client_authentication requires s2s_tcp_ssl_enabled'),
    'bad hec_metadata': ('splunk_hec { state_directory => "/tmp/n5d" hec_metadata => "everything" }', 'hec_metadata must be full, id_only or none'),
    'mtls without ca': ('splunk_hec { state_directory => "/tmp/n6" ssl_client_authentication => true }', 'mTLS requires an explicit client CA'),
    'keystore and pem': ('splunk_hec { state_directory => "/tmp/n7" ssl_keystore => "/tmp/files/hec.p12" ssl_keystore_password => "changeit" ssl_certificate => "/tmp/files/hec.crt" ssl_key => "/tmp/files/hec.pkcs8.key" }', 'choose keystore or PEM'),
    'tcp cap above expanded': ('splunk_hec { state_directory => "/tmp/n8" s2s_tcp_max_event_bytes => 1073741824 }', 'must not exceed max_expanded_bytes'),
    'tcp default index not allowed': ('splunk_hec { state_directory => "/tmp/n9" s2s_tcp_default_index => "x" s2s_tcp_indexes => "a,b" }', 'TCP default index must be allowed'),
    'bad token json': ('splunk_hec { state_directory => "/tmp/n10" tokens_json => \'[{"token":"a","bogus":1}]\' }', 'unknown inline token key'),
    'duplicate token': ('splunk_hec { state_directory => "/tmp/n11" tokens_json => \'[{"token":"a"},{"token":"a"}]\' }', 'duplicate token identity'),
    'shared state directory': ('splunk_hec { id => "x" state_directory => "/tmp/n12" port => 18101 }\n  splunk_hec { id => "y" state_directory => "/tmp/n12" port => 18102 }', 'ACK state already owned'),
}
SETUP = r'''
set -e
mkdir -p /tmp/files /tmp/state
J=/usr/share/logstash/jdk/bin
cp /work/examples/hec-inputs.conf /tmp/files/hec-inputs.conf
$J/keytool -genkeypair -alias server -keyalg RSA -keysize 2048 -storetype PKCS12 -keystore /tmp/files/hec.p12 \
  -storepass changeit -dname CN=test -ext SAN=dns:localhost -validity 30 -noprompt >/dev/null 2>&1
$J/keytool -exportcert -rfc -alias server -keystore /tmp/files/hec.p12 -storepass changeit > /tmp/files/hec.crt 2>/dev/null
cp /tmp/files/hec.crt /tmp/files/clients-ca.pem
openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/files/k.pem -out /tmp/files/hec.crt -subj /CN=test \
  -addext subjectAltName=DNS:localhost -days 30 >/dev/null 2>&1
openssl pkcs8 -topk8 -nocrypt -in /tmp/files/k.pem -out /tmp/files/hec.pkcs8.key
/usr/share/logstash/bin/logstash-plugin install --local --no-verify /work/logstash-input-splunk_hec-0.1.0-java.gem >/dev/null 2>&1
set +e
export HEC_TOKENS_JSON='[{"token":"11111111-1111-4111-8111-111111111111","index":"main","indexes":"main,app","useACK":false}]'
export APP_TOKENS_JSON='[{"token":"22222222-2222-4222-8222-222222222222"}]'
export FWD_TOKENS_JSON='[{"token":"33333333-3333-4333-8333-333333333333"}]'
export HEC_P12_PASSWORD=changeit
export ELASTICSEARCH_URL=http://localhost:9200 ELASTICSEARCH_API_KEY=test
for f in /conf/*.conf; do
  n=$(basename $f .conf)
  out=$(/usr/share/logstash/bin/logstash -t -f $f --path.data /tmp/data-$n 2>&1)
  if echo "$out" | grep -q "Configuration OK"; then echo "RESULT $n OK"; else echo "RESULT $n FAIL"; echo "$out" | grep -E "ERROR|FATAL|Reason" | head -5 | sed "s/^/  /"; fi
done
'''

def main():
    if len(BLOCKS) < 4:
        raise SystemExit('expected the documented configuration snippets, found %d' % len(BLOCKS))
    failures = []
    report = {'positive': [], 'negative': []}
    for role in ('minimum', 'latest'):
        with tempfile.TemporaryDirectory(dir=str(ROOT / 'build')) as raw:
            conf = Path(raw)
            conf.chmod(0o755)
            for i, block in enumerate(BLOCKS):
                (conf / ('doc%02d.conf' % i)).write_text(prepare(block))
            for i, text in enumerate(EXAMPLES):
                (conf / ('example%02d.conf' % i)).write_text(prepare(text))
            for name, (body, _) in NEGATIVE.items():
                slug = re.sub(r'\W+', '_', name)
                (conf / ('neg_%s.conf' % slug)).write_text('input {\n  %s\n}\noutput { stdout { } }\n' % body)
            output = runtime.docker('run', '--rm', '--entrypoint', 'bash', '-v', str(ROOT) + ':/work:ro',
                                    '-v', str(conf) + ':/conf:ro', runtime.P['logstash.%s.image' % role],
                                    '-c', SETUP, timeout=1800)
            results = {}
            detail = {}
            current = None
            for line in output.splitlines():
                m = re.match(r'RESULT (\S+) (OK|FAIL)', line)
                if m:
                    current = m.group(1)
                    results[current] = m.group(2)
                    detail[current] = []
                elif current and line.startswith('  '):
                    detail[current].append(line.strip())
            for i, block in enumerate(BLOCKS):
                name = 'doc%02d' % i
                ok = results.get(name) == 'OK'
                report['positive'].append({'role': role, 'snippet': i, 'ok': ok, 'errors': detail.get(name, [])})
                if not ok:
                    failures.append((role, name, detail.get(name), block[:200]))
            for i in range(len(EXAMPLES)):
                name = 'example%02d' % i
                ok = results.get(name) == 'OK'
                report['positive'].append({'role': role, 'example': i, 'ok': ok, 'errors': detail.get(name, [])})
                if not ok:
                    failures.append((role, name, detail.get(name), EXAMPLES[i][:200]))
            for name, (_, expected) in NEGATIVE.items():
                key = 'neg_' + re.sub(r'\W+', '_', name)
                failed = results.get(key) == 'FAIL'
                matched = expected is None or any(expected in e for e in detail.get(key, []))
                report['negative'].append({'role': role, 'case': name, 'rejected': failed, 'message_matched': matched,
                                           'errors': detail.get(key, [])[:2]})
                if not (failed and matched):
                    failures.append((role, name, detail.get(key), 'expected rejection containing: %s' % expected))
    report['artifact'] = runtime.artifact_info()
    report['status'] = 'pass' if not failures else 'fail'
    report['snippets'] = len(BLOCKS)
    report['example_pipelines'] = len(EXAMPLES)
    (ROOT / 'tests/interop/evidence/config-check.json').write_text(json.dumps(report, indent=2) + '\n')
    for f in failures:
        print('FAIL', f)
    print(report['status'].upper(), len(BLOCKS), 'documented snippets,', len(EXAMPLES), 'example pipelines,', len(NEGATIVE), 'negative cases, 2 runtimes')
    return 0 if not failures else 1

if __name__ == '__main__':
    sys.exit(main())
