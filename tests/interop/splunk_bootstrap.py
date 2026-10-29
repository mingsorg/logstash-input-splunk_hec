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
    """Start the real Splunk daemon with its own CLI and return its PID once it is stable.

    Steps: refuse to run anywhere but an explicitly owned disposable container; make the config and
    var directories writable by the service user; seed the admin password on first start; run
    ``splunk start``; then wait until the daemon's PID file names a live, non-zombie process and write
    a readiness marker that the test harness polls. Nothing here fakes a forwarder: it is the vendor
    binary started the way an administrator would start it, minus the slow Ansible provisioning that
    the official entrypoint runs.
    """
    home=Path(home)
    # Safety guard: this script changes file ownership and starts a daemon, so it must never run on a
    # developer machine or an unmarked container.
    if not Path('/.dockerenv').exists() or not os.environ.get('HEC_FIXTURE_OWNED'):
        raise RuntimeError('native bootstrap requires an explicitly owned Docker fixture')
    if str(home) not in ('/opt/splunk','/opt/splunkforwarder'):
        raise RuntimeError('unexpected fixture SPLUNK_HOME')
    # A stale marker from an earlier start must not make the harness think we are already ready.
    READY.unlink(missing_ok=True)
    (home/'var').mkdir(parents=True,exist_ok=True)
    local=home/'etc/system/local'
    local.mkdir(parents=True,exist_ok=True)
    passwd=home/'etc/passwd'
    # First start only: Splunk reads user-seed.conf once to create the admin account. The password
    # is a throwaway test value for a disposable container.
    if not passwd.exists() or not passwd.stat().st_size:
        (local/'user-seed.conf').write_text('[user_info]\nUSERNAME = admin\nPASSWORD = '+password+'\n')
    # The image's volumes can be root-owned; splunkd runs as the "splunk" user and must be able to write.
    account=pwd.getpwnam('splunk')
    os.chown(home,account.pw_uid,account.pw_gid)
    subprocess.run(['chown','-R','splunk:splunk',str(home/'etc'),str(home/'var')],check=True,timeout=120)
    # The helper runs once as a new container's bootstrap. Runtime files from a
    # stopped/restarted fixture must not be mistaken for an active new daemon.
    (home/'var/run/splunk/splunkd.pid').unlink(missing_ok=True)
    # Run the CLI as the service user with a matching HOME/USER; a root HOME makes splunk create
    # root-owned files that the daemon then cannot update.
    environment=dict(os.environ,HOME=account.pw_dir,USER='splunk',LOGNAME='splunk')
    before=time.monotonic()
    result=subprocess.run([str(home/'bin/splunk'),'start','--accept-license','--answer-yes','--no-prompt'],
        cwd=home,env=environment,user=account.pw_uid,group=account.pw_gid,
        capture_output=True,text=True,timeout=timeout)
    print(result.stdout,flush=True)
    if result.stderr:print(result.stderr,flush=True)
    if result.returncode:
        # Surface the daemon's own logs so a failed fixture start is diagnosable from the test output.
        for filename in ('splunkd_stderr.log','splunkd.log'):
            path=home/'var/log/splunk'/filename
            if path.exists():print(path.read_text(errors='replace')[-16000:],flush=True)
        raise RuntimeError('native Splunk start failed with exit '+str(result.returncode))
    # ``splunk start`` can return slightly before the PID file settles (it briefly shows a restart marker).
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
    """Keep the container's main process alive for as long as the Splunk daemon is.

    The container's foreground process is this loop. If the daemon exits (or fails to come back within
    30 s of a self-restart, which Splunk does after some configuration changes) the loop raises, the
    container stops, and the harness reports the failure instead of waiting on a dead sender.
    """
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
