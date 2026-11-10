#!/usr/bin/env python3
"""Execute current inspection tests, never qualify stale Linux XML by name alone."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import uuid
import xml.etree.ElementTree as ET
import runtime
from inspection_contract import validate

SUITE = 'org.logstashplugins.hec.S2SAssemblyInspectorTest'
RECOVERY_SUITE = 'org.logstashplugins.hec.S2SAssemblyRecoveryTest'


def tree_digest(root):
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob('*') if p.is_file()):
        digest.update(path.relative_to(root).as_posix().encode() + b'\0' + hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def source_digest():
    digest = hashlib.sha256()
    paths = sorted(runtime.ROOT.glob('src/**/*.java')) + [runtime.ROOT/'build.gradle']
    for path in paths:
        digest.update(path.relative_to(runtime.ROOT).as_posix().encode() + b'\0' + hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def run_suite(host_fresh=False):
    artifact, validators = runtime.artifact_info(), runtime.validators_info()
    run_id = uuid.uuid4().hex
    report = dict(artifact=artifact, validators=validators, source_sha256=source_digest(), run_id=run_id, status='fail')
    native = platform.system() == 'Linux' and host_fresh
    build = runtime.ROOT/'build' if native else runtime.ROOT/'build/linux-inspection'
    log = runtime.ROOT/'build/linux-inspection-run.log'
    try:
        if not native:
            gradle = runtime.ROOT/'.cache'/('gradle-'+runtime.P['gradle.version'])/'bin/gradle'
            cache = Path(os.environ.get('GRADLE_USER_HOME', str(Path.home()/'.gradle'))).resolve()
            if not gradle.is_file() or not cache.is_dir():
                raise RuntimeError('prepare pinned Gradle and its dependency cache first')
            output = runtime.docker('run', '--rm', '--network', 'none', '--user', 'root',
                '-e', 'JAVA_HOME=/usr/share/logstash/jdk', '-e', 'GRADLE_USER_HOME=/gradle-cache',
                '-v', str(cache)+':/gradle-cache', '-v', str(runtime.ROOT)+':'+str(runtime.ROOT),
                '-w', str(runtime.ROOT), '--entrypoint', '/bin/bash', runtime.P['logstash.latest.image'],
                str(gradle), '--offline', '--no-daemon', '--rerun-tasks', '--max-workers=1',
                '-PinspectionLinux', '-PinspectionRunId='+run_id,
                'test', '--tests', SUITE, '--tests', RECOVERY_SUITE, timeout=1800)
            log.write_text(output)
        xml = build/'test-results/test'/('TEST-'+SUITE+'.xml')
        suite = ET.fromstring(xml.read_bytes())
        assert int(suite.get('tests')) >= 11
        assert all(int(suite.get(field)) == 0 for field in ('failures', 'errors', 'skipped'))
        report.update(status='pass', xml=xml.relative_to(runtime.ROOT).as_posix(),
            xml_sha256=hashlib.sha256(xml.read_bytes()).hexdigest(),
            main_classes_sha256=tree_digest(build/'classes/java/main'),
            test_classes_sha256=tree_digest(build/'classes/java/test'),
            tests=int(suite.get('tests')), cases=[case.get('name') for case in suite.findall('testcase')],
            execution='fresh-host-linux' if native else 'fresh-pinned-linux-container')
        recovery_xml=build/'test-results/test'/('TEST-'+RECOVERY_SUITE+'.xml')
        assert recovery_xml.is_file(), 'missing fresh recovery test results'
        recovery=ET.fromstring(recovery_xml.read_bytes())
        assert int(recovery.get('tests'))>=10 and all(int(recovery.get(field))==0 for field in ('failures','errors','skipped'))
        report['recovery']={'xml':recovery_xml.relative_to(runtime.ROOT).as_posix(),'sha256':hashlib.sha256(recovery_xml.read_bytes()).hexdigest(),
            'tests':int(recovery.get('tests')),'cases':[case.get('name') for case in recovery.findall('testcase')]}
        captures=build/'inspection-captures'/('manual' if native else run_id)/'captured.json'
        captured=json.loads(captures.read_text())
        assert captured['run_id']==('manual' if native else run_id)
        help=captured['help']
        for case in captured['cases']:
            if case['stdout']!='':validate(help['output_schema'],case['stdout'])
            if case['stderr']!='':validate(help['warning_schema'] if case['status']==2 else help['error_schema'],case['stderr'])
        # A weakened required-field/authority schema must not validate these controls.
        complete=next(case['stdout'] for case in captured['cases'] if case['status']==0 and case['stdout']['format']=='v3')
        for key in ('pending','sequence','outbox'):
            bad=dict(complete);bad.pop(key)
            try:validate(help['output_schema'],bad)
            except ValueError:pass
            else:raise AssertionError('schema accepted missing '+key)
        bad=dict(complete,format='v2')
        try:validate(help['output_schema'],bad)
        except ValueError:pass
        else:raise AssertionError('schema accepted inconsistent authority')
        report.update(schema_captures=captures.relative_to(runtime.ROOT).as_posix(),
            schema_captures_sha256=hashlib.sha256(captures.read_bytes()).hexdigest(),schema_outputs_validated=True)
        assert source_digest() == report['source_sha256'] and runtime.artifact_info() == artifact and runtime.validators_info() == validators
    except Exception as failure:
        report['status']='fail'
        log.write_text(getattr(failure, 'stdout', '') or str(failure))
        report['error'] = type(failure).__name__
        raise
    finally:
        (runtime.EVIDENCE/'linux-inspection.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


if __name__ == '__main__':
    print(json.dumps(run_suite(), indent=2))
