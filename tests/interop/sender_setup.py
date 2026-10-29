"""Provision ONLY a disposable sender container. Execute with its bundled Python."""
import os
from pathlib import Path
import shutil
import subprocess
import time

home=Path(os.environ['SPLUNK_HOME'])
if not (home/'etc/splunk-launch.conf').exists():
    subprocess.run(['/sbin/updateetc.sh'],check=True)
print('sender setup: etc initialized',flush=True)
app=home/'etc/apps/hec_sender/local'
app.mkdir(parents=True,exist_ok=True)
(app/'outputs.conf').write_text('''[httpout]
httpEventCollectorToken = 55555555-5555-4555-8555-555555555555
uri = http://host.docker.internal:18090
batchSize = 65536
batchTimeout = 1

[indexAndForward]
index = false
''')
if os.environ.get('HEC_RECEIVER_URI'):
    outputs=(app/'outputs.conf').read_text().replace('http://host.docker.internal:18090',os.environ['HEC_RECEIVER_URI'])
    if os.environ['HEC_RECEIVER_URI'].startswith('https:'):
        outputs=outputs.replace('[httpout]\n','[httpout]\nsslVerifyServerCert = true\nsslVerifyServerName = true\n',1)
        shutil.copyfile('/tmp/hec-server.crt',app/'trusted-hec.crt')
        (app/'trusted-hec.crt').chmod(0o644)
        (app/'server.conf').write_text('[sslConfig]\nsslRootCAPath = '+str(app/'trusted-hec.crt')+'\n')
    (app/'outputs.conf').write_text(outputs)
# --- Classic TCP forwarding (HEC_TRANSPORT=tcp) ----------------------------------------------------
# Replaces the httpout configuration above with a tcpout group aimed at the plugin's TCP listener.
# HEC_TCP_ACK    -> useACK (ask the receiver to acknowledge records after they are queued)
# HEC_TCP_COMPRESSED -> compressed (request the compact zlib record stream)
# HEC_TCP_TLS    -> useSSL plus certificate AND hostname verification against the plugin's own
#                   generated certificate, which the harness mounts at /tmp/hec-server.crt.
if os.environ.get('HEC_TRANSPORT')=='tcp':
    receiver=os.environ['HEC_TCP_RECEIVER']
    tls=os.environ.get('HEC_TCP_TLS','false')=='true'
    group=('[tcpout]\ndefaultGroup = capture\nindexAndForward = false\n'
        '[tcpout:capture]\nserver = '+receiver+'\nsendCookedData = true\n'
        'useACK = '+os.environ.get('HEC_TCP_ACK','true')+'\ncompressed = '+os.environ.get('HEC_TCP_COMPRESSED','false')+'\n')
    if tls:
        # Real sender trust/name verification against the generated plugin identity.
        group+='useSSL = true\nsslVerifyServerCert = true\nsslVerifyServerName = true\n'
        shutil.copyfile('/tmp/hec-server.crt',app/'trusted-hec.crt')
        (app/'trusted-hec.crt').chmod(0o644)
        (app/'server.conf').write_text('[sslConfig]\nsslRootCAPath = '+str(app/'trusted-hec.crt')+'\n')
    (app/'outputs.conf').write_text(group+'[indexAndForward]\nindex = false\n')
(app/'inputs.conf').write_text('''[monitor://$SPLUNK_HOME/var/log/splunk]
disabled = true

[monitor:///tmp/hec-source.log]
disabled = false
index = main
sourcetype = hec_native_text
crcSalt = <SOURCE>

[monitor:///tmp/hec-source.json]
disabled = false
index = main
sourcetype = hec_native_json
crcSalt = <SOURCE>
''')
(app/'props.conf').write_text('''[hec_native_json]
INDEXED_EXTRACTIONS = json
TIMESTAMP_FIELDS = time
TIME_FORMAT = %s.%9N
SHOULD_LINEMERGE = false

[hec_native_text]
SHOULD_LINEMERGE = false
DATETIME_CONFIG = CURRENT
''')
(app/'limits.conf').write_text('[thruput]\nmaxKBps = 0\n')
# The fixture only forwards data. Each sender has its own bridge namespace;
# retain management for the official entrypoint's readiness checks.
with (app/'server.conf').open('a') as configuration:
    configuration.write('\n[kvstore]\ndisabled = true\n')
(app/'web.conf').write_text('[settings]\nstartwebserver = false\n')
for name,content in [('log','alpha\n  indented remains separate\n重复\nrepeat\nrepeat\n'),
                     ('json','{"time":"1790000000.123456789","message":"native","a.b":["first","second"],"host":"payload-host"}\n')]:
    Path('/tmp/hec-source.'+name).write_text(content)
subprocess.run(['chown','-R','splunk:splunk',str(app.parent)],check=True)
print('sender setup: app configured',flush=True)
if os.environ.get('HEC_STARTUP_MODE')=='direct':
    from splunk_bootstrap import start,supervise
    supervise(start(home,'HecSender-Test-Only-487!'),home)
# Delegate first-start provisioning and process supervision to the image's own
# entrypoint, as used by the working oracle fixture. A direct CLI start can emit
# traffic before returning and bypasses the image's initialization/health state.
os.environ['SPLUNK_START_ARGS']='--accept-license'
os.environ['SPLUNK_PASSWORD']='HecSender-Test-Only-487!'
print('sender setup: handing off to official entrypoint',flush=True)
os.execv('/sbin/entrypoint.sh',['/sbin/entrypoint.sh','start-service'])
