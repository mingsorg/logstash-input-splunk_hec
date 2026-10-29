#!/usr/bin/env python3
"""Verify the install flows documented in docs/installation.md in real Logstash containers.

For each supported runtime (the pinned minimum 9.5.0 and latest 9.5.5 images) a fresh container:

1. installs the built gem with ``logstash-plugin install <gem>`` (no extra flags);
2. checks ``logstash-plugin list --verbose`` shows ``logstash-input-splunk_hec (0.1.0)``;
3. validates a pipeline with ``logstash -t``;
4. runs a real pipeline using the DEFAULT TLS settings (generated certificate), waits for ``/health``,
   posts an event with curl while verifying the certificate, and checks the event came out;
5. reinstalls the same gem (idempotent), then removes it and confirms it disappears from ``list`` and
   that a pipeline using it then fails with a clear "Couldn't find any input plugin" error.

Additionally: a Docker image is built from docker/Dockerfile.logstash and a pipeline is validated inside
it, and installation on Logstash 9.4.0 (older than the 9.5.0 floor) must be REJECTED at install time.
Evidence goes to tests/interop/evidence/install-check.json and names the gem digest. The gem is installed
from the local file; the only downloads are the Logstash images themselves.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import runtime

ROOT = runtime.ROOT
OLD_IMAGE = 'docker.elastic.co/logstash/logstash:9.4.0'   # deliberately older than the 9.5.0 floor
EXPECTED_STEPS = 11

# Executed INSIDE each container. It prints one "STEP <name> OK|FAIL" line per check, which the host parses.
INSIDE = r'''
L=/usr/share/logstash/bin/logstash-plugin
LS=/usr/share/logstash/bin/logstash
step() { if [ "$2" = 0 ]; then echo "STEP $1 OK"; else echo "STEP $1 FAIL"; fi; }

# 1-2. Install from the local gem file and confirm Logstash lists it.
$L install /work/logstash-input-splunk_hec-0.1.0-java.gem > /tmp/install.log 2>&1; step install $?
$L list --verbose splunk 2>&1 | grep -q "logstash-input-splunk_hec (0.1.0)"; step list_shows_plugin $?

# 3. Validate a minimal pipeline. state_directory is persistent in real deployments.
mkdir -p /tmp/state
cat > /tmp/pipeline.conf <<'CONF'
input {
  splunk_hec {
    id => "install-check"
    state_directory => "/tmp/state"
    port => 18088
    tokens_json => '[{"token":"11111111-1111-4111-8111-111111111111"}]'
  }
}
output { stdout { codec => rubydebug } }
CONF
$LS -t -f /tmp/pipeline.conf --path.data /tmp/data-t 2>&1 | grep -q "Configuration OK"; step config_test $?

# 4. Run it for real. TLS is the default, so a certificate is generated under state_directory on first start.
($LS -f /tmp/pipeline.conf --path.data /tmp/data-run > /tmp/run.log 2>&1 &)
CERT=/tmp/state/identity/server.crt
for i in $(seq 1 120); do
  [ -f $CERT ] && curl -s --cacert $CERT -o /dev/null https://localhost:18088/services/collector/health && break
  sleep 1
done
# curl verifies the certificate chain AND the hostname (localhost is in the default SANs).
curl -s --cacert $CERT https://localhost:18088/services/collector/health | grep -q "HEC is healthy"; step tls_health $?
RESP=$(curl -s --cacert $CERT -H "Authorization: Splunk 11111111-1111-4111-8111-111111111111" \
  https://localhost:18088/services/collector/event -d '{"event":{"msg":"install-check"},"sourcetype":"demo"}')
echo "$RESP" | grep -q '"code":0'; step event_accepted $?
sleep 3
grep -q "install-check" /tmp/run.log; step event_in_output $?
# A request without a token must be refused.
CODE=$(curl -s -o /dev/null -w '%{http_code}' --cacert $CERT https://localhost:18088/services/collector/event -d '{"event":"x"}')
test "$CODE" = 401; step no_token_rejected $?
pkill -f "logstash.*pipeline.conf"; sleep 3

# 5. Reinstall is idempotent; remove really removes, and the failure afterwards is clear.
$L install /work/logstash-input-splunk_hec-0.1.0-java.gem > /tmp/reinstall.log 2>&1; step reinstall $?
$L remove logstash-input-splunk_hec > /tmp/remove.log 2>&1; step remove $?
$L list --verbose splunk 2>&1 | grep -q "logstash-input-splunk_hec"; if [ $? -ne 0 ]; then step gone_from_list 0; else step gone_from_list 1; fi
$LS -t -f /tmp/pipeline.conf --path.data /tmp/data-t2 2>&1 | grep -q "Couldn't find any input plugin named 'splunk_hec'"; step clear_error_after_remove $?
'''

# Executed in the OLD image: installation must be refused with a version-conflict message and leave nothing behind.
INSIDE_OLD = r'''
/usr/share/logstash/bin/logstash-plugin install /work/logstash-input-splunk_hec-0.1.0-java.gem > /tmp/old.log 2>&1
echo "EXIT $?"
grep -E "Plugin version conflict|logstash-core >= 9.5.0" /tmp/old.log | head -2
echo "LISTED $(/usr/share/logstash/bin/logstash-plugin list splunk 2>&1 | grep -c logstash-input-splunk_hec)"
'''


def run_container(image, script):
    """Run ``script`` in a throwaway container with the repository mounted read-only at /work."""
    return runtime.docker('run', '--rm', '--entrypoint', 'bash', '-v', str(ROOT) + ':/work:ro',
                          image, '-c', script, timeout=1800)


def parse_steps(output):
    """Turn the container's ``STEP name OK|FAIL`` lines into {name: bool}."""
    return {line.split()[1]: line.split()[2] == 'OK' for line in output.splitlines() if line.startswith('STEP ')}


def docker_image_check():
    """Build an image from docker/Dockerfile.logstash and validate a pipeline using the plugin inside it."""
    gem = sorted(ROOT.glob('logstash-input-splunk_hec-*-java.gem'))[-1]
    tag = 'logstash-splunk-hec-install-check'
    with tempfile.TemporaryDirectory(dir=str(ROOT / 'build')) as context:
        context = Path(context)
        # The Dockerfile expects the gem next to it, exactly as the installation guide instructs.
        (context / gem.name).write_bytes(gem.read_bytes())
        (context / 'Dockerfile.logstash').write_text((ROOT / 'docker/Dockerfile.logstash').read_text())
        subprocess.run(['docker', 'build', '-q', '-f', str(context / 'Dockerfile.logstash'),
                        '--build-arg', 'LOGSTASH_IMAGE=' + runtime.P['logstash.latest.image'], '-t', tag, str(context)],
                       check=True, capture_output=True, timeout=1800)
    try:
        # state_directory lives on a NAMED volume at /var/lib/logstash/hec, which must be writable by the
        # image's logstash user (the Dockerfile creates the directory with that ownership).
        script = ('echo \'input { splunk_hec { state_directory => "/var/lib/logstash/hec" } } output { stdout {} }\' > /tmp/p.conf; '
                  '/usr/share/logstash/bin/logstash-plugin list --verbose splunk; '
                  '/usr/share/logstash/bin/logstash -t -f /tmp/p.conf --path.data /tmp/d 2>&1 | grep -E "Configuration OK|ERROR|FATAL"; '
                  'ls /var/lib/logstash/hec/identity')
        volume = tag + '-state'
        output = runtime.docker('run', '--rm', '--entrypoint', 'bash', '-v', volume + ':/var/lib/logstash/hec', tag, '-c', script, timeout=900)
        return {'built': True, 'plugin_listed': 'logstash-input-splunk_hec (0.1.0)' in output,
                'config_ok': 'Configuration OK' in output,
                # The plugin generated its TLS identity on the named volume, proving the volume was writable.
                'state_volume_writable': 'server.crt' in output}
    finally:
        subprocess.run(['docker', 'rmi', '-f', tag], capture_output=True, timeout=120)
        subprocess.run(['docker', 'volume', 'rm', '-f', tag + '-state'], capture_output=True, timeout=120)


def main():
    artifact = runtime.artifact_info()
    report = {'artifact': artifact, 'runtimes': {}, 'status': 'fail'}
    failures = []
    for role in ('minimum', 'latest'):
        image = runtime.P['logstash.%s.image' % role]
        steps = parse_steps(run_container(image, INSIDE))
        report['runtimes'][role] = {'image': image, 'logstash': runtime.P['logstash.' + role], 'steps': steps}
        failures += ['%s:%s' % (role, name) for name, ok in steps.items() if not ok]
        if len(steps) < EXPECTED_STEPS:
            # A script that died early must not look like a pass just because nothing printed FAIL.
            failures.append('%s: only %d of %d steps ran' % (role, len(steps), EXPECTED_STEPS))
    report['docker_image'] = docker_image_check()
    if not all(report['docker_image'][k] for k in ('plugin_listed', 'config_ok', 'state_volume_writable')):
        failures.append('docker image build/validate')
    subprocess.run(['docker', 'pull', '-q', OLD_IMAGE], capture_output=True, timeout=1800)
    old = run_container(OLD_IMAGE, INSIDE_OLD)
    rejected = 'EXIT 0' not in old and 'Plugin version conflict' in old and 'LISTED 0' in old
    report['pre_floor_rejected'] = {'image': OLD_IMAGE, 'output': old.splitlines()[-4:], 'rejected': rejected}
    if not rejected:
        failures.append('Logstash 9.4.0 install was not rejected')
    if runtime.artifact_info() != artifact:
        failures.append('artifact changed during the check')
    report['status'] = 'pass' if not failures else 'fail'
    (ROOT / 'tests/interop/evidence/install-check.json').write_text(json.dumps(report, indent=2) + '\n')
    for item in failures:
        print('FAIL', item)
    print(report['status'].upper(), 'install flows on 9.5.0, 9.5.5, the Docker image, and the 9.4.0 rejection')
    return 0 if not failures else 1


if __name__ == '__main__':
    sys.exit(main())
