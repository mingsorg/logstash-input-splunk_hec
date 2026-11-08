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
import review_journal

def raw_reviewer_verdict(text):
    """Find one verdict object in prose/fences without counting its nested objects."""
    decoder=json.JSONDecoder();objects=[];position=0
    while position<len(text):
        start=text.find('{',position)
        if start<0:break
        try:
            value,end=decoder.raw_decode(text,start)
        except ValueError:
            position=start+1;continue
        if isinstance(value,dict):objects.append(value)
        position=end
    if len(objects)!=1:raise ValueError('missing or ambiguous raw reviewer verdict')
    return objects[0]

def review_complete(identity,artifact,validators,root):
    try:
        if not isinstance(identity,dict):return False
        _,source,claims=review_journal.reviewed_source(root)
        if identity.get('artifact')!=artifact or identity.get('validators')!=validators or identity.get('source_sha256')!=source or identity.get('claims_file')!=review_journal.CLAIMS or identity.get('claims_sha256')!=claims:return False
        reports=identity['reports']
        if len(reports)!=3 or {item['lens'] for item in reports}!=set(review_journal.LENSES):return False
        paths=[(root/item['file']).resolve() for item in reports]
        if len(set(paths))!=3 or any(not path.is_relative_to(root.resolve()) for path in paths):return False
        native_sessions=set()
        for item,path in zip(reports,paths):
            data=path.read_bytes()
            if hashlib.sha256(data).hexdigest()!=item.get('sha256'):return False
            result=json.loads(data)
            if not isinstance(result,dict):return False
            proof=result.get('structured_output',{})
            if result.get('provider')=='opencode-task':
                session=result.get('reviewer_session_id');text=result.get('text')
                if not isinstance(session,str) or not session.strip() or session in native_sessions:return False
                if not isinstance(text,str) or not text.strip():return False
                if raw_reviewer_verdict(text)!=proof:return False
                native_sessions.add(session)
            else:
                # Retain the original Claude CLI proof requirements; native Task
                # records have no CLI process exit or token-usage metadata.
                if result.get('provider') not in (None,'claude-cli'):return False
                usage=result.get('usage')
                if item.get('exit_code')!=0 or result.get('is_error',True) or not isinstance(usage,dict) or not usage.get('input_tokens',0):return False
            if proof!={'lens':item['lens'],'source_sha256':source,'claims_sha256':claims,'artifact_sha256':artifact['sha256'],'verdict':'pass','findings':[]}:return False
        return True
    except (OSError,KeyError,TypeError,ValueError):return False

def soak_row_valid(row):
    # Derive from the tested quota, not a producer-supplied bound assertion.
    return row.get('quota')==8192 and row['events']>=2000 and row['peak_physical_bytes']<=8*8192+32768 and row.get('transient_publication_samples',0)>0 and row['compactions']>0 and row['memory_released']

def real_growth_progress(row):
    actual=row.get('producer_actual_contributions',0);cap=row.get('producer_contribution_cap',0)
    return 2<=actual<=cap<=32 and row.get('contribution_limit')==10000 and row.get('retained_contributions_after_progress')==row['lines']+actual and row['lines']+actual<10000 and 0<row.get('concurrent_unrelated_sender_ns',0)<=5_000_000_000

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
    upgrade=read('upgrade-check.json');checks['upgrade_baseline_pinned']=upgrade['baseline']['sha256']==upgrade['baseline'].get('pinned_sha256')
    upgrade=read('upgrade-check.json');checks['live_stateful_upgrade_traffic']=len(upgrade.get('runtimes',[]))==2 and all('LIVE_BEFORE_OK' in r.get('output','') and 'LIVE_AFTER_OK' in r.get('output','') and 'ASSEMBLY_MIGRATION_OK' in r.get('output','') for r in upgrade['runtimes'])
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
    checks['java_tests']=len(java)>=9 and sum(s['tests'] for s in java)>=125 and all(not(s['failures'] or s['errors'] or s['skipped']) for s in java)
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
                           'directRecordAckWaitsForQueueInsertionAndFailedInsertionIsNotAcknowledged',
                           'rejectedRequestsLogAValueFreeRateLimitedReason','legacyIgnoredUnselectedRecordCreatesNoGateStateOrBarrier',
                           'httpDirectRecordWaitsBehindBlockedSameSenderPredecessorAtTheListener','httpMixedBatchReachesTheQueueInExactWireOrder',
                           'tcpDirectRecordWaitsBehindBlockedSameSenderPredecessorAndIsAckedAfterInsertion',
                            'httpCoordinatesAndTimestampFlagsAreIndependent'})
    required_cases.update({'fixedContributionsHaveBoundedTransactionBytesAndExactCachedCapacity',
                           'arbitraryRequestsReplayAgainstReferenceAndRetriesDoNotAppend',
                           'everyIncompleteHeaderAndPayloadSuffixTruncatesButCompleteCorruptionFails',
                           'authenticatedInvalidOperationsAndSequencesFailClosed',
                           'migrationInterruptionsPreserveOriginalAndOldReaderRefusal',
                           'invalidPublishedPointerNeverFallsBackToOldSnapshotOrBackup',
                           'compactionPublicationFaultsRecoverAuthoritativeGenerationWithinPhysicalBound',
                           'appendFaultsRetainAcknowledgedPrefixAndMayReplayUnacknowledgedCommit'})
    required_cases.add('receiptEvictionAndReinsertionPreservesCommitOrderAcrossReplay')
    required_cases.update({'changedEventLimitRestartContinueRestartIsReplayable','replacedPendingOrderMatchesTimeoutDeliveryAcrossRecovery',
                           'drainedHistoricalStateRestartsWithLoweredQuota','nullRecoveredOutputEnvelopeFailsBeforePublication',
                           'saturatedReceiptAccountingDoesNotTraverseReceiptMap','freshPublicationCrashBoundariesRefuseLegacyReaderAndRetainAcceptedState',
                           'disabledRulesRejectRetainedV3WithoutLegacyMarkerMaskingDetection'})
    required_cases.update({'recoveredPointerDirectoryIsSyncedBeforeCleanup','missingPublishedPointerNeverResetsFreshOrMigratedWork',
                           'oversizedPreservedBackupFailsBeforeHealthyRecovery','malformedTaggedEnvelopesAreRejected',
                           'authenticatedReceiptOverwriteFailsWithUnchangedJournal','fullCompletionByteLimitRejectsEscapingGrowthAndRetainsCompletablePrefix',
                           'subprocessHaltPublicationReopensExactAcknowledgedState','oversizedStateRefusalComparisonIsBoundedAndNonmutating'})
    migration=read('assembly-migration.json')
    checks['v2_stateful_migration']=migration.get('status')=='pass' and migration.get('artifact')==artifact and migration.get('validators')==validators and len(migration.get('runs',[]))==2 and all(
        all(row.get(key) is True for key in ('pending_retained','outbox_retained','receipts_retained','backup_exact','old_reader_refused','continuation_matches','retry_suppressed')) for row in migration['runs'])
    scaling=read('journal-scaling.json')
    checks['journal_scaling']=scaling.get('status')=='pass' and scaling.get('artifact')==artifact and scaling.get('validators')==validators and {row['lines'] for row in scaling.get('runs',[])}=={500,1000,2000,4000,8000} and all(
        row['max_transaction_bytes']<8192 and row['heap_peak_observed_bytes']>0 and row['memory_released'] and row['unrelated_sender_progress'] and row['finalization_ns']>0 and row.get('replay_ns',0)>0 and real_growth_progress(row) for row in scaling['runs'])
    checks['long_compaction_restart']=scaling.get('long_state_compaction',{}).get('long_compaction_ns',0)>0 and scaling.get('long_state_compaction',{}).get('compacted_restart_ns',0)>0 and scaling.get('long_state_compaction',{}).get('complete_equivalence') is True and scaling.get('long_state_compaction',{}).get('pending_contributions',0)>=500
    halts=scaling.get('process_halt_publication',[])
    checks['process_halt_publication']=len(halts)==11 and len({row['boundary'] for row in halts})==11 and all(row['exit_code']==73 and row['reopened'] for row in halts)
    saturated=scaling.get('saturated_receipts',{})
    checks['saturated_receipts']=saturated.get('receipts')==4096 and saturated.get('checks',0)>=1000 and saturated.get('receipt_map_traversals')==0 and saturated.get('memory_released') is True
    soak=read('assembly-soak.json')
    checks['bounded_soak']=soak.get('status')=='pass' and soak.get('artifact')==artifact and soak.get('validators')==validators and {row['role'] for row in soak.get('runs',[])}=={'minimum','latest'} and all(
        soak_row_valid(row) for row in soak['runs'])
    checks['matrix_test_cases']={name+'()' for name in required_cases}<={name for suite in java for name in suite['cases']}
    suite=unittest.defaultTestLoader.discover(str(runtime.ROOT/'tests/build'))
    log=io.StringIO()
    with contextlib.redirect_stdout(log),contextlib.redirect_stderr(log):
        result=unittest.TextTestRunner(stream=log,verbosity=2).run(suite)
    checks['python_tests']=result.wasSuccessful() and result.testsRun>=21
    review_file=runtime.EVIDENCE/'independent-review.md'
    review={'status':'incomplete','report':review_file.relative_to(runtime.ROOT).as_posix(),'sha256':hashlib.sha256(review_file.read_bytes()).hexdigest() if review_file.is_file() else None}
    identity_file=runtime.EVIDENCE/'review-identity.json'
    if identity_file.is_file():
        identity=json.loads(identity_file.read_text())
        if review_complete(identity,artifact,validators,runtime.ROOT):review['status']='complete'
    report={'artifact':artifact,'validators':validators,'package_manifest_sha256':package_manifest,
            'status':'pass' if all(checks.values()) else 'fail','checks':checks,'java':java,
            'java_tests':sum(s['tests'] for s in java),'python_tests':result.testsRun,'python_output':log.getvalue(),
            'independent_review':review,
            'release_ready':False}
    report['release_ready']=report['status']=='pass' and review['status']=='complete'
    (runtime.EVIDENCE/'qualification-summary.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('artifact','status','checks','java_tests','python_tests','independent_review','release_ready')},indent=2))
    return 0 if report['status']=='pass' else 1

if __name__=='__main__':sys.exit(main())
