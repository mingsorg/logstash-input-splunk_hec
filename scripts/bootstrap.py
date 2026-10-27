#!/usr/bin/env python3
"""Pinned bootstrap. Extract compile-only API from the selected distribution image."""
import hashlib
import fcntl
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
P = dict(s.split('=', 1) for s in (ROOT/'versions.properties').read_text().splitlines()
         if s and not s.startswith('#'))
CACHE = ROOT/'.cache'

def extract_api(image, destination):
    cid = subprocess.check_output(['docker', 'create', image], text=True, timeout=120).strip()
    try:
        subprocess.run(['docker', 'cp', cid+':/usr/share/logstash/logstash-core/lib/jars', str(destination)], check=True, timeout=120)
    finally:
        subprocess.run(['docker', 'rm', '-v', cid], check=True, timeout=60)


def ensure_api(image, cache):
    api = cache/'logstash-jars'
    manifest = api/'.source-image'
    if (api/'logstash-core.jar').is_file() and manifest.is_file() and manifest.read_text()==image:
        return
    if api.is_symlink():
        raise RuntimeError('API cache must not be a symlink')
    with tempfile.TemporaryDirectory(prefix='.hec-api-', dir=cache) as temporary:
        stage = Path(temporary)/'jars'
        extract_api(image, stage)
        if not (stage/'logstash-core.jar').is_file():
            raise RuntimeError('incomplete extracted Logstash API')
        (stage/'.source-image').write_text(image)
        backup = Path(temporary)/'previous'
        if api.exists():
            api.rename(backup)
        try:
            stage.rename(api)
        except BaseException:
            if backup.exists():backup.rename(api)
            raise


def main():
    CACHE.mkdir(exist_ok=True)
    version = P['gradle.version']
    with (CACHE/'bootstrap.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not (CACHE/f'gradle-{version}/bin/gradle').exists():
            with urllib.request.urlopen(f'https://downloads.gradle.org/distributions/gradle-{version}-bin.zip', timeout=120) as r:
                data = r.read()
            if hashlib.sha256(data).hexdigest() != P['gradle.sha256']:
                raise SystemExit('Gradle distribution checksum mismatch')
            archive = CACHE/f'gradle-{version}.zip'
            archive.write_bytes(data)
            with zipfile.ZipFile(archive) as z:z.extractall(CACHE)
            (CACHE/f'gradle-{version}/bin/gradle').chmod(0o755)
        ensure_api(P['logstash.latest.image'], CACHE)
    if sys.argv[1:2]==['--run-gradle']:
        executable=str(CACHE/f'gradle-{version}/bin/gradle')
        os.execv(executable,[executable,'--project-dir',str(ROOT),*sys.argv[2:]])


if __name__=='__main__':main()
