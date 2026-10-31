"""Read-only helpers for the existing lab. No container lifecycle operations."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

NAMES = ('hec-demo-indexer', 'hec-demo-logstash', 'hec-demo-uf')
LAB = Path(__file__).resolve().parents[1]


def docker(*arguments):
    return subprocess.check_output(['docker', *arguments], text=True, timeout=60).strip()


def inspect():
    rows = json.loads(docker('inspect', *NAMES))
    result = {row['Name'].lstrip('/'): row for row in rows}
    if set(result) != set(NAMES):
        raise RuntimeError('the three existing lab containers are required')
    ownership = {row['Config'].get('Labels', {}).get('hec.demo.run') for row in rows}
    if len(ownership) != 1 or None in ownership or '' in ownership:
        raise RuntimeError('containers do not share the existing lab ownership label')
    return result


def mount(row, destination):
    matches = [entry for entry in row['Mounts'] if entry['Destination'] == destination]
    if len(matches) != 1:
        raise RuntimeError('missing or ambiguous mount: ' + destination)
    return matches[0]


def port(row, container_port):
    values = row['NetworkSettings']['Ports'].get(str(container_port) + '/tcp') or []
    values = [value for value in values if value['HostIp'] == '127.0.0.1']
    if len(values) != 1:
        raise RuntimeError('expected one loopback-published port: ' + str(container_port))
    return int(values[0]['HostPort'])


def credentials(rows, state_dir=None):
    state = Path(state_dir).expanduser().resolve() if state_dir else Path(mount(rows[NAMES[0]], '/demo')['Source'])
    value = json.loads((state / 'connection.json').read_text())
    required = ('username', 'password', 'input_token', 'indexer_hec_token', 'run_id')
    if any(not isinstance(value.get(key), str) or not value[key] for key in required):
        raise RuntimeError('connection.json is incomplete')
    if any(row['Config']['Labels']['hec.demo.run'] != value['run_id'] for row in rows.values()):
        raise RuntimeError('connection.json does not belong to these containers')
    return state, value


def report_path(path):
    directory = LAB / 'reports'
    if directory.is_symlink():
        raise ValueError('the reports directory must not be a symlink')
    path = Path(os.path.abspath(Path(path).expanduser()))
    if path.parent != directory or path.suffix != '.json' or path.is_symlink():
        raise ValueError('reports must be direct .json files under docker/test-lab/reports, not symlinks')
    if path.exists():
        previous = json.loads(path.read_text())
        if previous.get('mode') != 'read-only existing-lab verification':
            raise ValueError('refusing to overwrite a file that is not a previous validation report')
    return path


def save_report(path, value):
    path = report_path(path)
    path.parent.mkdir(mode=0o700, exist_ok=True)
    path.parent.chmod(0o700)
    descriptor, temporary = tempfile.mkstemp(prefix='.validation-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as handle:
            handle.write(json.dumps(value, indent=2, ensure_ascii=False) + '\n')
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def reverse_lines(path, max_bytes=64 << 20):
    """Yield complete lines newest-first, retaining at most the last 64 MiB."""
    with Path(path).open('rb') as handle:
        position = handle.seek(0, 2)
        scanned = 0
        remainder = b''
        discard_tail = True
        while position and scanned < max_bytes:
            size = min(1 << 20, position, max_bytes - scanned)
            position -= size
            handle.seek(position)
            pieces = (handle.read(size) + remainder).split(b'\n')
            remainder = pieces[0]
            complete = pieces[1:]
            if complete and discard_tail:
                complete.pop()  # EOF's empty or incomplete final segment.
                discard_tail = False
            yield from (line for line in reversed(complete) if line)
            scanned += size
        if position == 0 and not discard_tail and remainder:
            yield remainder
