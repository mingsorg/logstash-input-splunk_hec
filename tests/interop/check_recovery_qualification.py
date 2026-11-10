#!/usr/bin/env python3
"""Fail-closed 0.6.0 gate: new recovery plus every prior exact-artifact guarantee."""
import json
import hashlib
import re
from collections import Counter
import xml.etree.ElementTree as ET
import sys
import runtime
import linux_inspection_tests
import check_metrics_qualification

CLAIMS='docs/recovery-export-0.6.0.md'
PRIOR=('assembly.json','assembly-disk-full.json','indexed-assembly.json','wire-assembly.json','config-check.json','install-check.json',
       'upgrade-check.json','runtime.json','reproducibility.json','queue-cancellation.json','assembly-migration.json',
       'journal-scaling.json','assembly-soak.json','inspection.json','metrics.json','metrics-overhead-investigation.json','review-identity.json')
EXPECTED={name:(status,command) for name,status,command in (
    ('complete-corrupt',3,None),('no-authority',3,None),('archive-tampered',3,None),('archive-existing',5,None),
    ('directory-existing',5,None),('symlink',5,None),('fifo',5,None),('locked',4,None),('missing-runtime',70,None),
    ('shared-lock',0,'export'),('read-only-owner',0,'export'),('reexport-incomplete',2,'export'))}
for label,status in (('published-v3',0),('original-v2',0),('typed-blocked-incompatible',0),('short-header',2),('short-payload',2)):
    EXPECTED[label]=(status,'export');EXPECTED[label+'-rebuild']=(status,'rebuild')


def integer(value,minimum=0):return type(value) is int and minimum<=value<=2**63-1


def origin_valid(origin,depth=0):
    if depth>16 or not isinstance(origin,dict) or set(origin)!={'source','completeness','previous'}:return False
    source,complete,previous=(origin[key] for key in ('source','completeness','previous'))
    if not isinstance(source,dict) or set(source)!={'format','authority','generation','snapshot_sequence','sequence'}:return False
    if not isinstance(complete,dict) or set(complete)!={'classification','omitted_range'}:return False
    if previous is not None and not origin_valid(previous,depth+1):return False
    if source['format']=='v2':
        if source['authority']!='original_v2' or any(source[key] is not None for key in ('generation','snapshot_sequence','sequence')) or previous is not None:return False
    elif source['format']=='v3':
        if source['authority']!='published_v3' or not integer(source['generation'],1) or not integer(source['snapshot_sequence']) or not integer(source['sequence']) or source['sequence']<source['snapshot_sequence']:return False
    else:return False
    omitted=complete['omitted_range']
    if omitted is not None and (source['format']!='v3' or not isinstance(omitted,dict) or set(omitted)!={'offset','length'} or not integer(omitted['offset']) or not integer(omitted['length'],1) or omitted['offset']+omitted['length']>2*67108863+4096):return False
    inherited=previous is not None and previous['completeness']['classification']=='incomplete_prefix'
    return (complete['classification']=='complete' and omitted is None and not inherited or
            complete['classification']=='incomplete_prefix' and (omitted is not None or inherited))


def summary_valid(value,label,status,command):
    keys={'schema_version','command','classification','restart_compatibility','origin','byte_count','sha256','archive_bytes','pending','outbox','receipts','blocked','contributions'}
    if not isinstance(value,dict) or set(value)!=keys:return False
    if type(value['schema_version']) is not int or value['schema_version']!=1 or value['command']!=command or value['restart_compatibility']!='not_evaluated':return False
    if value['classification']!=('complete' if status==0 else 'incomplete_prefix') or not origin_valid(value['origin']) or value['origin']['completeness']['classification']!=value['classification']:return False
    if not isinstance(value['sha256'],str) or re.fullmatch('[a-f0-9]{64}',value['sha256']) is None:return False
    if not integer(value['byte_count'],1) or not integer(value['archive_bytes'],1) or not value['byte_count']<value['archive_bytes']<=67108863+65536:return False
    typed=label.startswith('typed-blocked-incompatible')
    for field,count in {'pending':1,'outbox':3 if typed else 1,'receipts':2 if typed else 1,'contributions':1}.items():
        if type(value[field]) is not int or value[field]!=count:return False
    if value['blocked'] is not typed:return False
    expected_format='v2' if typed or label.startswith('original-v2') else 'v3'
    if value['origin']['source']['format']!=expected_format:return False
    if label.startswith(('short-header','short-payload')) and value['origin']['completeness']['omitted_range'] is None:return False
    if label=='reexport-incomplete' and (value['origin']['previous'] is None or value['origin']['previous']['completeness']['classification']!='incomplete_prefix'):return False
    return True


def valid(report,artifact,validators):
    try:
        if report.get('status')!='pass' or report.get('artifact')!=artifact or report.get('validators')!=validators:return False
        rows=report['runs']
        if len(rows)!=2 or {r['role'] for r in rows}!={'minimum','latest'}:return False
        for row in rows:
            if row['status']!='pass' or row['image']!=runtime.P['logstash.'+row['role']+'.image'] or row['network']!='none':return False
            if not all(row.get(key) is True for key in ('independent_full_state','isolated_copy_full_state','types_order','read_only_source','unprivileged_owner',
                'schemas_validated','parent_ack_tls_unchanged','no_checkout','no_compiler_at_runtime','no_python_at_runtime')):return False
            counts=Counter(case['case'] for case in row['cases'])
            if counts!=Counter({case:2 if case=='reexport-incomplete' else 1 for case in EXPECTED}):return False
            summaries={};reexports=[]
            for case in row['cases']:
                if set(case)!={'case','exit_code','inventory_unchanged','summary'}:return False
                label=case['case'];status,command=EXPECTED[label]
                if type(case.get('exit_code')) is not int or case['exit_code']!=status or case.get('inventory_unchanged') is not True:return False
                if command is None:
                    if case.get('summary') is not None:return False
                elif not summary_valid(case.get('summary'),label,status,command):return False
                else:
                    summaries[label]=case['summary']
                    if label=='reexport-incomplete':reexports.append(case['summary']['origin']['previous'])
            for label in ('published-v3','original-v2','typed-blocked-incompatible','short-header','short-payload'):
                if {key:value for key,value in summaries[label].items() if key!='command'}!={key:value for key,value in summaries[label+'-rebuild'].items() if key!='command'}:return False
            if Counter(json.dumps(value,sort_keys=True) for value in reexports)!=Counter(json.dumps(summaries[label]['origin'],sort_keys=True) for label in ('short-header','short-payload')):return False
            adoptions=row.get('adoptions',[])
            if Counter(proof['case'] for proof in adoptions)!=Counter({'published-v3':1,'original-v2':1,'short-header':1,'short-payload':1}):return False
            for proof in adoptions:
                if not all(proof.get(key) is True for key in ('compatible_adoption','continuation','drained','preserved_ids','sender_order','retry_suppression')):return False
                original,final=proof['original_ids'],proof['finalized_ids']
                if not isinstance(original,list) or len(original)!=1 or not isinstance(final,list) or len(final)!=2 or final[:1]!=original or any(not isinstance(key,str) or not key for key in final) or len(set(final))!=2:return False
        return True
    except (KeyError,TypeError,ValueError):return False


def linux_valid(report,artifact,validators):
    try:
        if report.get('status')!='pass' or report.get('artifact')!=artifact or report.get('validators')!=validators or report.get('source_sha256')!=linux_inspection_tests.source_digest():return False
        source=runtime.ROOT/'src/test/java/org/logstashplugins/hec/S2SAssemblyRecoveryTest.java'
        cases={name+'()' for name in re.findall(r'@Test\s+void\s+(\w+)\s*\(',source.read_text())}
        proof=report['recovery']
        if not cases or type(proof['tests']) is not int or proof['tests']!=len(cases) or Counter(proof['cases'])!=Counter(cases):return False
        path=(runtime.ROOT/proof['xml']).resolve()
        if not path.is_relative_to(runtime.ROOT.resolve()) or hashlib.sha256(path.read_bytes()).hexdigest()!=proof['sha256']:return False
        xml=ET.fromstring(path.read_bytes())
        return int(xml.get('tests'))==len(cases) and all(int(xml.get(key))==0 for key in ('errors','failures','skipped')) and Counter(node.get('name') for node in xml.findall('testcase'))==Counter(cases)
    except (OSError,KeyError,TypeError,ValueError,ET.ParseError):return False


def main():
    artifact,validators=runtime.artifact_info(),runtime.validators_info()
    def read(name):
        try:return json.loads((runtime.EVIDENCE/name).read_text())
        except (OSError,ValueError):return {}
    recovery_valid=valid(read('recovery.json'),artifact,validators)
    missing=[name for name in PRIOR if not (runtime.EVIDENCE/name).is_file()]
    if missing:
        summary={'artifact':artifact,'validators':validators,'status':'fail','release_ready':False,
            'checks':{'installed_recovery':recovery_valid,'prior_evidence_present':False},'missing_evidence':missing,
            'independent_review':{'status':'incomplete'}}
    else:
        # Preserve every existing matrix assertion, fresh Java/package comparison, metrics and review requirement.
        check_metrics_qualification.CLAIMS=CLAIMS
        check_metrics_qualification.main()
        summary=read('qualification-summary.json')
        summary['checks']['installed_recovery']=recovery_valid
    linux=read('linux-inspection.json')
    summary['checks']['linux_recovery_tests']=linux_valid(linux,artifact,validators)
    summary['status']='pass' if all(summary['checks'].values()) else 'fail'
    summary['release_ready']=summary['status']=='pass' and summary['independent_review']['status']=='complete'
    (runtime.EVIDENCE/'recovery-qualification-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary,indent=2))
    return 0 if summary['release_ready'] else 1


if __name__=='__main__':sys.exit(main())
