"""Configure an owned oracle before its first native Splunk CLI startup."""
import os
from pathlib import Path
import shutil
from splunk_bootstrap import start,supervise

if not Path('/.dockerenv').exists() or not os.environ.get('HEC_FIXTURE_OWNED'):
    raise RuntimeError('oracle bootstrap must run inside an owned Docker fixture')
home=Path(os.environ['SPLUNK_HOME'])
if not (home/'etc/splunk-launch.conf').exists():
    import subprocess
    subprocess.run(['/sbin/updateetc.sh'],check=True)
app=home/'etc/apps/hec_oracle/local'
app.mkdir(parents=True,exist_ok=True)
for name in ('inputs','props'):shutil.copyfile('/tmp/hec-'+name+'.conf',app/(name+'.conf'))
(app/'web.conf').write_text('[settings]\nstartwebserver = false\n')
(app/'server.conf').write_text('[kvstore]\ndisabled = true\n')
# A separate app keeps this receiver enabled when the HTTP-oracle config is
# recaptured/reloaded. TCP is plaintext only inside this disposable capture lab.
tcp=home/'etc/apps/hec_tcp_receiver/local'
tcp.mkdir(parents=True,exist_ok=True)
(tcp/'inputs.conf').write_text('[splunktcp://9997]\ndisabled = false\n')
supervise(start(home,'HecOracle-Test-Only-487!'),home)
