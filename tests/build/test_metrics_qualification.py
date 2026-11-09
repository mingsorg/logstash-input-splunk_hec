"""Fail-closed controls for installed metrics and measured overhead evidence."""
import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests/interop'))
import check_metrics_qualification as gate
import metrics
import run


class MetricsQualificationTest(unittest.TestCase):
    def overhead(self):
        return {'enabled':{'samples':180,'median_ns':110,'p99_ns':110},'disabled':{'samples':180,'median_ns':100,'p99_ns':100},
            'median_overhead_percent':100*(110/100-1),'requires_investigation':True,'events_per_request':32,
            'rounds':[{'round':n,'samples_ns':{'enabled':[110]*60,'disabled':[100]*60},'median_overhead_percent':100*(110/100-1)} for n in (1,2,3)]}

    def report(self):
        rows=[]
        for role in ('minimum','latest'):
            zero={key:-1 if key.endswith('epoch_millis') else 0 for key in metrics.schema()}
            observed={'direct':zero.copy(),'selected':zero.copy(),'disabled':None,'disabled_direct':None,'enabled_direct':zero.copy()}
            observed['selected']['assembly.enabled']=1
            row={'role':role,'status':'pass','image':gate.runtime.P['logstash.'+role+'.image'],
                **{k:copy.deepcopy(observed) for k in ('initial','deltas','before_restart','after_restart')},
                **{k:True for k in ('schema_exact','integer_scalars','disabled_absent','replay_handoffs_are_occurrences')},
                'blocked_scrape_seconds':.1,'blocked_scrape_deadline_seconds':2,'overhead':self.overhead(),
                'tcp_deltas':{'tcp.data.success':1,'tcp.data.failure':1,'tcp.control.success':1,'handoff.tcp.returned':2,'tcp.connection_closed':1}}
            row['deltas']['selected'].update({'assembly.contributions':4,'assembly.flush.new_start':1,'store.commit.count':3,'http.s2s.success':2})
            row['deltas']['direct'].update({'http.event.success':1,'http.event.invalid':1,'http.event.unauthorized':1,'http.event.forbidden':1,
                'http.raw.success':1,'http.ack.success':1,'http.unknown.invalid':1,'handoff.http_event.returned':3,'handoff.http_raw.returned':2})
            row['before_restart']['selected']['assembly.outbox']=1;row['before_restart']['direct']['handoff.active']=1
            row['after_restart']['selected'].update({'last_durable_acceptance_epoch_millis':-1,'handoff.outbox.returned':1})
            rows.append(row)
        return {'status':'pass','artifact':{'sha256':'gem'},'validators':'validators','runs':rows}

    def test_exact_reports_pass_but_stale_or_missing_runtimes_fail(self):
        report=self.report();self.assertTrue(gate.metrics_valid(report,report['artifact'],'validators'))
        self.assertFalse(gate.metrics_valid(report,{'sha256':'other'},'validators'))
        self.assertFalse(gate.metrics_valid(report,report['artifact'],'new-validator'))
        report['runs'][1]=copy.deepcopy(report['runs'][0])
        self.assertFalse(gate.metrics_valid(report,report['artifact'],'validators'))

    def test_wrong_counts_dynamic_labels_bool_scalars_and_disabled_metrics_fail(self):
        for phase,key,value in [('deltas','assembly.contributions',5),('initial','private-sender',0),('initial','assembly.enabled',True),('after_restart','assembly.contributions',1)]:
            report=self.report();report['runs'][0][phase]['selected'][key]=value
            self.assertFalse(gate.metrics_valid(report,report['artifact'],'validators'),(phase,key))
        report=self.report();report['runs'][0]['initial']['disabled']={}
        self.assertFalse(gate.metrics_valid(report,report['artifact'],'validators'))
        for mode,phase,key,value in [('selected','initial','assembly.contributions',1),('direct','initial','last_handoff_epoch_millis',0),
                                    ('direct','deltas','http.event.success',0),('direct','after_restart','handoff.http_event.returned',1),
                                    ('direct','initial','tcp.data.success',2**63)]:
            report=self.report();report['runs'][0][phase][mode][key]=value
            self.assertFalse(gate.metrics_valid(report,report['artifact'],'validators'),key)

    def test_overhead_is_recomputed_from_complete_positive_samples(self):
        self.assertTrue(gate.overhead_valid(self.overhead()))
        for mutate in (lambda v:v['enabled'].update(median_ns=1),lambda v:v.update(requires_investigation=False),
                       lambda v:v['rounds'][0]['samples_ns']['enabled'].pop(),lambda v:v['rounds'][0]['samples_ns']['enabled'].__setitem__(0,0)):
            value=self.overhead();mutate(value);self.assertFalse(gate.overhead_valid(value))

    def test_targeted_stage_only_runs_metrics(self):
        with patch.object(sys,'argv',['run.py','--stage','metrics']),patch.object(run,'run') as execute:
            self.assertEqual(0,run.main());execute.assert_called_once_with('metrics.py')


if __name__=='__main__':unittest.main()
