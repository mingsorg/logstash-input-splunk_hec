#!/usr/bin/env python3
"""Finite, real-distribution queue cancellation prerequisite. Nonzero means blocked."""
import json
from pathlib import Path
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
PROPS = dict(line.split('=', 1) for line in (ROOT / 'versions.properties').read_text().splitlines()
             if line and not line.startswith('#'))

def main():
    results = []
    for role in sys.argv[1:] or ['latest', 'minimum']:
        image = PROPS[f'logstash.{role}.image']
        name='hec-queue-'+uuid.uuid4().hex[:10]
        cmd = ['docker', 'run', '--rm', '--name', name, '--network', 'none', '-e',
               'JAVA_HOME=/usr/share/logstash/jdk', '--entrypoint',
               '/usr/share/logstash/vendor/jruby/bin/jruby', '-v', f'{ROOT}:/work:ro',
               image, '/work/tests/interop/queue_probe.rb']
        try:
            run = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            result = dict(role=role, image=image, exit_code=run.returncode,
                          stdout=run.stdout, stderr=run.stderr)
        except subprocess.TimeoutExpired as error:
            result = dict(role=role, image=image, exit_code=124, error=str(error))
        finally:
            subprocess.run(['docker','rm','-f','-v',name],capture_output=True,timeout=60)
        print(json.dumps(result, indent=2), flush=True)
        results.append(result)
    out = ROOT / 'tests/interop/evidence'
    out.mkdir(exist_ok=True)
    (out / 'queue-cancellation.json').write_text(json.dumps(results, indent=2) + '\n')
    return int(any(r['exit_code'] for r in results))

if __name__ == '__main__':
    sys.exit(main())
