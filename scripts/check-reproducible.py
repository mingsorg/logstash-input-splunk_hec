#!/usr/bin/env python3
"""Clean-build the gem twice and retain byte-for-byte reproducibility evidence."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
hashes=[]
for attempt in range(2):
    subprocess.run([str(ROOT/'gradlew'),'clean','gem'],cwd=ROOT,check=True,timeout=300)
    artifact=ROOT/'logstash-input-splunk_hec-0.1.0-java.gem'
    hashes.append(hashlib.sha256(artifact.read_bytes()).hexdigest())
report={'artifact':artifact.name,'sha256s':hashes,'byte_identical':len(set(hashes))==1,
        'source_date_epoch':1792972800,'clean_builds':2}
(ROOT/'tests/interop/evidence/reproducibility.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
if not report['byte_identical']:raise SystemExit('gem is not reproducible')
