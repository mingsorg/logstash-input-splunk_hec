#!/usr/bin/env python3
"""Fail-closed final-artifact evidence gate; independent review remains a separate gate."""
import contextlib
import io
import hashlib
import json
import sys
import subprocess
import tarfile
import unittest
import xml.etree.ElementTree as ET
import runtime

def packaged_files_match_build():
    """Compare, never replace, the selected gem against a fresh jar and packaged files."""
    root=runtime.ROOT
    jar_name='logstash-input-splunk_hec-'+runtime.VERSION+'.jar'
    jar=root/'build/libs'/jar_name
    expected={'vendor/jars/'+jar_name:jar.read_bytes()}
    for pattern in ('lib/**/*','docs/**/*','examples/**/*','README.md','LICENSE','NOTICE',
                    'VERSION','versions.properties','logstash-input-splunk_hec.gemspec'):
        for path in root.glob(pattern):
            if path.is_file():expected[path.relative_to(root).as_posix()]=path.read_bytes()
    with tarfile.open(runtime.GEM,'r:') as gem:
        with tarfile.open(fileobj=gem.extractfile('data.tar.gz'),mode='r:gz') as data:
            observed={}
            for member in data.getmembers():
                if not member.isfile():continue
                if member.name in observed:raise RuntimeError('duplicate packaged path: '+member.name)
                observed[member.name]=data.extractfile(member).read()
    if observed!=expected:
        changed=sorted(name for name in set(expected)|set(observed) if expected.get(name)!=observed.get(name))
        raise RuntimeError('selected gem does not match freshly tested build/package files: '+', '.join(changed))
    return {name:hashlib.sha256(value).hexdigest() for name,value in sorted(observed.items())}

def main():
    artifact=runtime.artifact_info();checks={};validators=runtime.validators_info()
    subprocess.run(['./gradlew','test','jar','--rerun-tasks','--max-workers=1'],cwd=runtime.ROOT,check=True,timeout=900)
    package_manifest=packaged_files_match_build()
    if runtime.artifact_info()!=artifact:raise RuntimeError('selected artifact changed during fresh tests')
    checks['fresh_tested_package_identity']=True
    def read(name):return json.loads((runtime.EVIDENCE/name).read_text())
    for name in ('assembly.json','assembly-disk-full.json','indexed-assembly.json','wire-assembly.json','config-check.json','install-check.json','upgrade-check.json'):
        report=read(name);checks[name]=report.get('status')=='pass' and report.get('artifact')==artifact and report.get('validators')==validators
    assembly=read('assembly.json')
    expected={(role,queue,transport,sender) for role in ('minimum','latest') for queue in ('memory','persisted')
              for transport in ('http','tcp') for sender in ('uf','hf')}
    checks['real_sender_matrix']={(r['runtime_role'],r['queue'],r['transport'],r['sender']) for r in assembly['runs'] if r['status']=='pass'}==expected
    checks['provenance_modes']={r['mode'] for r in assembly['runs']}=={'full','id_only','none'}
    wire=read('wire-assembly.json')
    checks['fresh_wire_captures']={(r['sender'],r['transport']) for r in wire['runs'] if r['status']=='pass'}=={(sender,transport) for sender in ('uf','hf') for transport in ('http','tcp')}
    for row in wire['runs']:
        for item in row['wire_capture']['items']:
            payload=(runtime.ROOT/item['file']).read_bytes()
            checks['fresh_wire_captures'] &= len(payload)==item['bytes'] and hashlib.sha256(payload).hexdigest()==item['sha256']
    checks['four_crash_probes']=len(assembly.get('recovery',[]))==4 and all(all(r.get(key) is True for key in
        ('sigkill_after_durable_success','ack_polled_before_kill','pending_snapshot_before_kill','old_ack_unknown_after_restart','tail_recovered','invalid_suffix_atomic','retry_suppressed')) for r in assembly['recovery'])
    indexed=read('indexed-assembly.json');controls=indexed.get('negative_controls',{})
    checks['indexed_only_negative_controls']=controls.get('rows',0)>0 and controls.get('rejected')==3*controls['rows']
    checks['first_contribution_time_across_restart']=len(assembly.get('timestamp_recovery',[]))==4 and all(r.get('first_contribution_time_retained') is True and r['first_time']!=r['later_time'] for r in assembly['timestamp_recovery'])
    upgrade=read('upgrade-check.json');checks['live_stateful_upgrade_traffic']=len(upgrade.get('runtimes',[]))==2 and all('LIVE_BEFORE_OK' in r.get('output','') and 'LIVE_AFTER_OK' in r.get('output','') for r in upgrade['runtimes'])
    runtimes=read('runtime.json')
    checks['legacy_runtime_matrix']={(r['role'],r['queue']) for r in runtimes if r.get('artifact')==artifact and 'error' not in r}=={(role,queue) for role in ('minimum','latest') for queue in ('memory','persisted')}
    reproducible=read('reproducibility.json')
    checks['reproducibility']=reproducible['byte_identical'] is True and reproducible['sha256s']==[artifact['sha256']]*2
    cancellation=read('queue-cancellation.json')
    probe_sha256=hashlib.sha256((runtime.ROOT/'tests/interop/queue_probe.rb').read_bytes()).hexdigest()
    checks['queue_cancellation']={r['role'] for r in cancellation if r['exit_code']==0 and
        r.get('artifact')==artifact and r.get('probe_sha256')==probe_sha256 and r.get('run_id')}=={'minimum','latest'}
    java=[]
    for path in sorted((runtime.ROOT/'build/test-results/test').glob('TEST-*.xml')):
        root=ET.parse(path).getroot()
        java.append({'suite':root.get('name'),'tests':int(root.get('tests')),'failures':int(root.get('failures')),
                     'errors':int(root.get('errors')),'skipped':int(root.get('skipped')),
                     'cases':[case.get('name') for case in root.findall('testcase')]})
    checks['java_tests']=len(java)==8 and sum(s['tests'] for s in java)>=110 and all(not(s['failures'] or s['errors'] or s['skipped']) for s in java)
    required_cases={'validationFailureRollsBackWholeBatchAndDefaultIdsRemainIdentical',
                    'concurrentStreamsRemainIsolatedUnderInterleavedCommits','inputNamespacesKeepIdenticalNativeSourcesAndAssembledIdsSeparate',
                    'emptyNativeRecordIsABlankLogicalLineAndUtf8CoordinatesAreRetained','metadataConflictGapReorderingAndStructuredTransitionDoNotOverwrite',
                    'orphanNewStartTimeoutAndLateContinuationAreDeterministic','deadlineAppliesBeforeLateContinuationEvenWhenTheWorkerHasNotRun',
                    'selectedHttpAckIsDurableBeforeQueueAndBadSuffixPreservesEarlierRequest',
                    'invalidRawSuffixIsValidatedBeforeOversizePrefixCanBlockEarlierAcceptedState',
                    'blockedQueueStopRetainsOutboxAndReplaysAfterHandoffWindow','durableOversizeBlockSurvivesRestartWithoutTruncatingAcceptedTail',
                     'selectedTcpAckPrecedesQueueAndReconnectContinuesTheDurableTail','tokenRevocationRejectsNewTrafficButDoesNotDiscardAcceptedAssembly'}
    required_cases.update({'admissionReservesTaggedFinalizationBeforeAcknowledgingPendingData',
                           'smallQuotaReceiptHistoryCannotFillAnOtherwiseDrainedStore',
                           'thousandLineEventFitsTheRequestBudgetWithoutRepeatedPrefixCharging',
                           'sameSenderOutputWaitsForDirectRecordWhileOtherSendersFlow',
                           'structuredRecordWaitsForEarlierSameSenderOutputEvenWithoutOtherStateChange',
                           'everyDirectSlotOrdersBothDirectionsIncludingIdenticalNoneModeOutputs',
                           'directEnqueueFailureReleasesSenderGate',
                           'concurrentHttpRequestsWaitForSameSenderButHostFallbackSeparatesHosts',
                           'httpFramingSelectsWireThenQueryThenTokenAndUnmatchedFallsBack',
                           'changedRetryHeaderTimezoneOrDatePartsConflictsBeforeAnyMutation',
                           'retryOfOldIndexCannotFinalizeNewIndexTail',
                           'legacyWireIdentityIsIndependentOfSelectedPositionlessOccurrenceScope',
                           'recoveryRejectsRetainedStateThatCannotFinalizeUnderTheConfiguredQuota',
                           'acknowledgedTailAboveJacksonDefaultStringLimitRecoversAfterRestart',
                           'enabledRuleDoesNotRejectDelimiterOnlyRecordWithDisallowedIndex',
                           'orphanAfterDirectRecordIsDeliveredInExactSenderOrder',
                           'failureOrRestartBeforeDirectHandoffIsAtLeastOnceWithoutLossOrDuplicates',
                           'directRecordAckWaitsForQueueInsertionAndFailedInsertionIsNotAcknowledged'})
    checks['matrix_test_cases']={name+'()' for name in required_cases}<={name for suite in java for name in suite['cases']}
    suite=unittest.defaultTestLoader.discover(str(runtime.ROOT/'tests/build'))
    log=io.StringIO()
    with contextlib.redirect_stdout(log),contextlib.redirect_stderr(log):
        result=unittest.TextTestRunner(stream=log,verbosity=2).run(suite)
    checks['python_tests']=result.wasSuccessful() and result.testsRun>=21
    report={'artifact':artifact,'validators':validators,'package_manifest_sha256':package_manifest,
            'status':'pass' if all(checks.values()) else 'fail','checks':checks,'java':java,
            'java_tests':sum(s['tests'] for s in java),'python_tests':result.testsRun,'python_output':log.getvalue(),
            'independent_review':{'status':'findings-open','report':'build/reviews/completion-review-0.2.0.md','reason':'Review ran and reported R1-R4 plus verification gaps; code fixes are in place but live matrix evidence must be regenerated and the result re-reviewed before release'},
            'release_ready':False}
    (runtime.EVIDENCE/'qualification-summary.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('artifact','status','checks','java_tests','python_tests','independent_review','release_ready')},indent=2))
    return 0 if report['status']=='pass' else 1

if __name__=='__main__':sys.exit(main())
