#!/usr/bin/env python3
"""0.5.0 gate: current installed metrics plus all prior ingestion/inspection guarantees."""
import json
import hashlib
import math
import statistics
import sys
import runtime
import metrics
import review_inspection
import check_inspection_qualification

CLAIMS='docs/ingestion-metrics-0.5.0.md'


def overhead_valid(value):
    try:
        rounds=value['rounds']
        if len(rounds)!=3 or [r['round'] for r in rounds]!=[1,2,3]:return False
        for mode in ('enabled','disabled'):
            samples=[n for r in rounds for n in r['samples_ns'][mode]]
            if any(len(r['samples_ns'][mode])!=60 for r in rounds) or any(type(n) is not int or n<=0 for n in samples):return False
            if value[mode]!={'samples':180,'median_ns':statistics.median(samples),'p99_ns':sorted(samples)[math.ceil(.99*len(samples))-1]}:return False
        for r in rounds:
            if r['median_overhead_percent']!=100*(statistics.median(r['samples_ns']['enabled'])/statistics.median(r['samples_ns']['disabled'])-1):return False
        percent=100*(value['enabled']['median_ns']/value['disabled']['median_ns']-1)
        return value['median_overhead_percent']==percent and value['requires_investigation'] is (percent>5) and value['events_per_request']==32
    except (KeyError,TypeError,ValueError,ZeroDivisionError):return False


def metrics_valid(report,artifact,validators):
    try:
        if report.get('status')!='pass' or report.get('artifact')!=artifact or report.get('validators')!=validators:return False
        rows=report['runs']
        if len(rows)!=2 or {r['role'] for r in rows}!={'minimum','latest'}:return False
        for r in rows:
            if r['status']!='pass' or r['image']!=runtime.P['logstash.'+r['role']+'.image']:return False
            for phase in ('initial','deltas','before_restart','after_restart'):
                observed=r[phase]
                if set(observed)!={'direct','selected','disabled','disabled_direct','enabled_direct'} or observed['disabled'] is not None or observed['disabled_direct'] is not None:return False
                for mode in ('direct','selected'):
                    if set(observed[mode])!=metrics.schema() or any(type(n) is not int for n in observed[mode].values()):return False
                    for key,n in observed[mode].items():
                        if not (-1 if key.endswith('epoch_millis') else 0)<=n<=2**63-1:return False
            for mode in ('direct','selected'):
                initial=r['initial'][mode]
                for key,n in initial.items():
                    if key.endswith('epoch_millis') and n!=-1:return False
                    if (key.startswith(('handoff.','assembly.flush.')) or key in ('assembly.contributions','store.commit.attempts')) and n!=0:return False
                if initial['assembly.enabled']!=(mode=='selected'):return False
            for key,n in {'http.event.success':1,'http.event.invalid':1,'http.event.unauthorized':1,'http.event.forbidden':1,
                          'http.raw.success':1,'http.ack.success':1,'http.unknown.invalid':1,'handoff.http_event.returned':3,'handoff.http_raw.returned':2}.items():
                if r['deltas']['direct'][key]!=n:return False
            if not all(r.get(k) is True for k in ('schema_exact','integer_scalars','disabled_absent','replay_handoffs_are_occurrences')):return False
            if not 0<r['blocked_scrape_seconds']<r['blocked_scrape_deadline_seconds']==2:return False
            for key,n in {'assembly.contributions':4,'assembly.flush.new_start':1,'store.commit.count':3,'http.s2s.success':2}.items():
                if r['deltas']['selected'][key]!=n:return False
            for key,n in {'tcp.data.success':1,'tcp.data.failure':1,'tcp.control.success':1,'handoff.tcp.returned':2,'tcp.connection_closed':1}.items():
                if r['tcp_deltas'][key]!=n:return False
            if r['before_restart']['selected']['assembly.outbox']<=0 or r['before_restart']['direct']['handoff.active']!=1:return False
            after=r['after_restart']['selected']
            if after['assembly.contributions']!=0 or after['last_durable_acceptance_epoch_millis']!=-1 or after['handoff.outbox.returned']<=0 or after['assembly.outbox']!=0:return False
            if r['after_restart']['direct']['handoff.http_event.returned']!=0:return False
            if not overhead_valid(r['overhead']):return False
        return True
    except (KeyError,TypeError,ValueError):return False


def main():
    artifact,validators=runtime.artifact_info(),runtime.validators_info()
    report=json.loads((runtime.EVIDENCE/'metrics.json').read_text())
    valid=metrics_valid(report,artifact,validators)
    investigation=json.loads((runtime.EVIDENCE/'metrics-overhead-investigation.json').read_text())
    investigated=investigation.get('artifact')==artifact and investigation.get('validators')==validators and investigation.get('status')=='complete'
    investigated=investigated and investigation.get('metrics_report_sha256')==hashlib.sha256((runtime.EVIDENCE/'metrics.json').read_bytes()).hexdigest()
    flagged={r['role'] for r in report.get('runs',[]) if r.get('overhead',{}).get('requires_investigation')}
    investigated=investigated and set(investigation.get('investigated_roles',[]))>=flagged and bool(investigation.get('analysis'))
    review_inspection.CLAIMS=CLAIMS
    original=check_inspection_qualification.main()
    summary=json.loads((runtime.EVIDENCE/'qualification-summary.json').read_text())
    summary['checks'].update(installed_metrics=valid,metrics_overhead_investigated=investigated,
        metrics_matrix_tests=any(s['suite']=='org.logstashplugins.hec.HecMetricsTest' and s['tests']>=17 and not(s['failures'] or s['errors'] or s['skipped']) for s in summary['java']))
    summary['status']='pass' if all(summary['checks'].values()) else 'fail'
    summary['release_ready']=summary['status']=='pass' and summary['independent_review']['status']=='complete'
    (runtime.EVIDENCE/'qualification-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({k:summary[k] for k in ('artifact','status','checks','independent_review','release_ready')},indent=2))
    return 0 if original==0 and summary['release_ready'] else 1


if __name__=='__main__':sys.exit(main())
