"""Minimal first-start bootstrap for explicitly owned disposable Splunk containers.

Run the official image's real splunk/splunkd binaries without the unrelated
Ansible roles. In particular, anonymous etc/var volumes must be writable by the
service UID, and subprocess USER/HOME must agree with that UID. Container
readiness is marked only after the real CLI start succeeds and its PID is alive.
"""
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import time


READY=Path('/tmp/hec-splunk-ready.json')


def daemon_pid(home):
    """Read the primary PID, ignoring worker-PID lines and transient restart markers."""
    try:
        lines=(Path(home)/'var/run/splunk/splunkd.pid').read_text().splitlines()
        if not lines:return None
        literal=lines[0].strip()
        if not re.fullmatch(r'[1-9][0-9]*',literal):return None
        pid=int(literal)
        os.kill(pid,0)
        status=Path('/proc')/str(pid)/'stat'
        if status.exists() and status.read_text().split(') ',1)[1].split()[0] in ('Z','X'):return None
        return pid
    except (OSError,ValueError,IndexError):return None


def start(home, password, timeout=300):
    home=Path(home)
    if not Path('/.dockerenv').exists() or not os.environ.get('HEC_FIXTURE_OWNED'):
        raise RuntimeError('native bootstrap requires an explicitly owned Docker fixture')
    if str(home) not in ('/opt/splunk','/opt/splunkforwarder'):
        raise RuntimeError('unexpected fixture SPLUNK_HOME')
    READY.unlink(missing_ok=True)
    (home/'var').mkdir(parents=True,exist_ok=True)
    local=home/'etc/system/local'
    local.mkdir(parents=True,exist_ok=True)
    passwd=home/'etc/passwd'
    if not passwd.exists() or not passwd.stat().st_size:
        (local/'user-seed.conf').write_text('[user_info]\nUSERNAME = admin\nPASSWORD = '+password+'\n')
    account=pwd.getpwnam('splunk')
    os.chown(home,account.pw_uid,account.pw_gid)
    subprocess.run(['chown','-R','splunk:splunk',str(home/'etc'),str(home/'var')],check=True,timeout=120)
    # The helper runs once as a new container's bootstrap. Runtime files from a
    # stopped/restarted fixture must not be mistaken for an active new daemon.
    (home/'var/run/splunk/splunkd.pid').unlink(missing_ok=True)
    environment=dict(os.environ,HOME=account.pw_dir,USER='splunk',LOGNAME='splunk')
    before=time.monotonic()
    result=subprocess.run([str(home/'bin/splunk'),'start','--accept-license','--answer-yes','--no-prompt'],
        cwd=home,env=environment,user=account.pw_uid,group=account.pw_gid,
        capture_output=True,text=True,timeout=timeout)
    print(result.stdout,flush=True)
    if result.stderr:print(result.stderr,flush=True)
    if result.returncode:
        for filename in ('splunkd_stderr.log','splunkd.log'):
            path=home/'var/log/splunk'/filename
            if path.exists():print(path.read_text(errors='replace')[-16000:],flush=True)
        raise RuntimeError('native Splunk start failed with exit '+str(result.returncode))
    deadline=time.monotonic()+60
    pid=None
    while time.monotonic()<deadline:
        pid=daemon_pid(home)
        if pid is not None:break
        time.sleep(.2)
    if pid is None:raise RuntimeError('native daemon did not reach a stable live PID after CLI startup')
    marker={'startup':'native-cli','pid':pid,'elapsed_seconds':round(time.monotonic()-before,3)}
    READY.write_text(json.dumps(marker)+'\n')
    print('hec fixture ready: '+json.dumps(marker),flush=True)
    return pid


def supervise(pid,home=None):
    while True:
        time.sleep(1)
        if home is None:os.kill(pid,0)
        else:
            current=daemon_pid(home)
            if current is None:
                deadline=time.monotonic()+30
                while current is None and time.monotonic()<deadline:
                    time.sleep(.2);current=daemon_pid(home)
                if current is None:raise RuntimeError('fixture daemon exited or failed to finish restart')
            pid=current
