"""Materialize the documented app files for an explicitly owned lab container."""
import os
from pathlib import Path
import subprocess
from splunk_bootstrap import private_write


def configure(role, expected_home):
    if not Path('/.dockerenv').exists() or not os.environ.get('HEC_FIXTURE_OWNED'):
        raise RuntimeError('bootstrap is only for an explicitly owned Docker test lab')
    home = Path(os.environ['SPLUNK_HOME'])
    if str(home) != expected_home:
        raise RuntimeError('unexpected SPLUNK_HOME for ' + role)
    if not (home / 'etc/splunk-launch.conf').exists():
        subprocess.run(['/sbin/updateetc.sh'], check=True, timeout=120)
    app = home / 'etc/apps/hec_chain_demo/local'
    app.mkdir(parents=True, exist_ok=True)
    variable = 'HEC_INPUT_TOKEN' if role == 'uf' else 'SPLUNK_HEC_TOKEN'
    token = os.environ[variable]
    if not token or any(char in token for char in '\r\n'):
        raise RuntimeError('missing or invalid ' + variable)
    placeholder = '<UF_TO_LOGSTASH_TOKEN>' if role == 'uf' else '<LOGSTASH_TO_SPLUNK_TOKEN>'
    source = Path(__file__).resolve().parents[2] / 'config' / role
    for template in sorted(source.glob('*.conf')):
        private_write(app / template.name, template.read_text().replace(placeholder, token))
    return home, app
