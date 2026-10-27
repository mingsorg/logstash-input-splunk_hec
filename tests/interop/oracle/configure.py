"""Executed as root only in the disposable oracle container after first startup."""
from pathlib import Path
import shutil
import os

app = Path('/opt/splunk/etc/apps/hec_oracle/local')
app.mkdir(parents=True, exist_ok=True)
for name in ('inputs', 'props'):
    shutil.copyfile(f'/tmp/hec-{name}.conf', app / f'{name}.conf')
    os.chown(app / f'{name}.conf', 41812, 41812)
os.chown(app, 41812, 41812)
