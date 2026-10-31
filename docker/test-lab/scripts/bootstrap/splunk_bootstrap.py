"""Native Splunk startup used by the existing lab; adapted from tests/interop/splunk_bootstrap.py."""
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import time

READY = Path('/tmp/hec-splunk-ready.json')


def private_write(path, text):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'w') as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(text)


def daemon_pid(home):
    try:
        lines = (Path(home) / 'var/run/splunk/splunkd.pid').read_text().splitlines()
        if not lines or not re.fullmatch(r'[1-9][0-9]*', lines[0].strip()):
            return None
        pid = int(lines[0].strip())
        os.kill(pid, 0)
        status = Path('/proc') / str(pid) / 'stat'
        if status.exists() and status.read_text().split(') ', 1)[1].split()[0] in ('Z', 'X'):
            return None
        return pid
    except (OSError, ValueError, IndexError):
        return None


def start(home, password, timeout=300):
    home = Path(home)
    if not Path('/.dockerenv').exists() or not os.environ.get('HEC_FIXTURE_OWNED'):
        raise RuntimeError('native bootstrap requires an explicitly owned Docker fixture')
    if str(home) not in ('/opt/splunk', '/opt/splunkforwarder'):
        raise RuntimeError('unexpected fixture SPLUNK_HOME')
    if not password or any(char in password for char in '\r\n'):
        raise RuntimeError('missing or invalid startup password')
    READY.unlink(missing_ok=True)
    (home / 'var').mkdir(parents=True, exist_ok=True)
    local = home / 'etc/system/local'
    local.mkdir(parents=True, exist_ok=True)
    passwd = home / 'etc/passwd'
    if not passwd.exists() or not passwd.stat().st_size:
        private_write(local / 'user-seed.conf', '[user_info]\nUSERNAME = admin\nPASSWORD = ' + password + '\n')
    account = pwd.getpwnam('splunk')
    os.chown(home, account.pw_uid, account.pw_gid)
    subprocess.run(['chown', '-R', 'splunk:splunk', str(home / 'etc'), str(home / 'var')],
                   check=True, timeout=120)
    (home / 'var/run/splunk/splunkd.pid').unlink(missing_ok=True)
    environment = dict(os.environ, HOME=account.pw_dir, USER='splunk', LOGNAME='splunk')
    before = time.monotonic()
    result = subprocess.run([str(home / 'bin/splunk'), 'start', '--accept-license', '--answer-yes', '--no-prompt'],
        cwd=home, env=environment, user=account.pw_uid, group=account.pw_gid,
        capture_output=True, text=True, timeout=timeout)
    print(result.stdout, flush=True)
    if result.stderr:
        print(result.stderr, flush=True)
    if result.returncode:
        for name in ('splunkd_stderr.log', 'splunkd.log'):
            path = home / 'var/log/splunk' / name
            if path.exists():
                print(path.read_text(errors='replace')[-16000:], flush=True)
        raise RuntimeError('native Splunk start failed with exit ' + str(result.returncode))
    deadline = time.monotonic() + 60
    pid = daemon_pid(home)
    while pid is None and time.monotonic() < deadline:
        time.sleep(.2)
        pid = daemon_pid(home)
    if pid is None:
        raise RuntimeError('native daemon did not reach a stable live PID')
    READY.write_text(json.dumps({'startup': 'native-cli', 'pid': pid,
                                'elapsed_seconds': round(time.monotonic() - before, 3)}) + '\n')
    return pid


def supervise(pid, home):
    while True:
        time.sleep(1)
        current = daemon_pid(home)
        if current is None:
            deadline = time.monotonic() + 30
            while current is None and time.monotonic() < deadline:
                time.sleep(.2)
                current = daemon_pid(home)
            if current is None:
                raise RuntimeError('daemon exited or failed to finish restart')
        pid = current
