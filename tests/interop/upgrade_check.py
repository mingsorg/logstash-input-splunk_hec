#!/usr/bin/env python3
"""Upgrade the explicit preserved 0.2.0 gem in disposable pinned runtimes only.

Pending/outbox/receipt equivalence is additionally qualified by journal_qualification.py.
"""
import hashlib
import json
import sys
import runtime
import assembly
import base64

BASELINE=runtime.ROOT/'logstash-input-splunk_hec-0.2.0-java.gem'
BASELINE_SHA256='3dbc0a7162c10d3c666562b274200cca487f2d96176b683bb8a6f598b06cdc11'
SCRIPT=r'''
set -e
L=/usr/share/logstash/bin/logstash-plugin
$L install --local --no-verify /work/@BASELINE@
$L list --verbose splunk | grep -F 'logstash-input-splunk_hec (0.2.0)'
mkdir -p /tmp/hec-upgrade
cat > /tmp/upgrade.conf <<'CONF'
input { splunk_hec { state_directory => "/tmp/hec-upgrade" ssl_enabled => false } }
output { stdout {} }
CONF
/usr/share/logstash/bin/logstash -t -f /tmp/upgrade.conf --path.data /tmp/before 2>&1 | grep 'Configuration OK'
sha256sum /tmp/hec-upgrade/* > /tmp/before.sha256
# --- live stateful traffic on the OLD plugin: ACK-enabled event, ACK confirmed, then a clean stop ---
mkdir -p /tmp/hec-live
cat > /tmp/live.conf <<'CONF'
input { splunk_hec { id => "stateful-upgrade" host => "127.0.0.1" port => 18088 ssl_enabled => false state_directory => "/tmp/hec-live"
  s2s_line_breaker_rules_json => '[{"match":"exact","sourcetype":"hec_assembly_selected","event_start_pattern":"^START","flush_timeout_ms":600000}]'
  tokens_json => '[{"token":"@TOKEN@","useACK":true}]' } }
output { file { path => "/tmp/live-out.ndjson" codec => json_lines flush_interval => 0 } }
CONF
start_ls(){
  /usr/share/logstash/bin/logstash -f /tmp/live.conf --path.data "$1" > "/tmp/ls-$2.log" 2>&1 &
  LS_PID=$!
  for i in $(seq 1 240); do (echo > /dev/tcp/127.0.0.1/18088) 2>/dev/null && return 0; sleep 1; done
  cat "/tmp/ls-$2.log"; return 1
}
stop_ls(){
  kill -TERM $LS_PID; for i in $(seq 1 90); do kill -0 $LS_PID 2>/dev/null || return 0; sleep 1; done
  kill -KILL $LS_PID; return 1
}
post_event(){
  curl -sS -H "Authorization: Splunk @TOKEN@" -H "X-Splunk-Request-Channel: @CHANNEL@" --data-binary "$1" http://127.0.0.1:18088/services/collector/event
}
poll_ack(){
  curl -sS -H "Authorization: Splunk @TOKEN@" -H "X-Splunk-Request-Channel: @CHANNEL@" --data-binary "{\"acks\":[$1]}" http://127.0.0.1:18088/services/collector/ack
}
wait_events(){ for i in $(seq 1 60); do [ "$(grep -c "$1" /tmp/live-out.ndjson 2>/dev/null)" -ge 1 ] && return 0; sleep 1; done; return 1; }
start_ls /tmp/live-before before
R1=$(post_event '{"event":"upgrade-before"}'); echo "BEFORE_RESPONSE $R1"
ACK1=$(echo "$R1" | grep -o '"ackId":[0-9]*' | cut -d: -f2); test -n "$ACK1"
wait_events upgrade-before
poll_ack "$ACK1" | grep -F "\"$ACK1\":true"
printf '%s' '@S2S_HEAD@' | base64 -d > /tmp/head.bin
printf '%s' '@S2S_TAIL@' | base64 -d > /tmp/tail.bin
printf '%s' '@S2S_END@' | base64 -d > /tmp/end.bin
post_s2s(){ curl -sS -H "Authorization: Splunk @TOKEN@" -H "X-Splunk-Request-Channel: @CHANNEL@" --data-binary "@$1" http://127.0.0.1:18088/services/collector/s2s; }
post_s2s /tmp/head.bin | grep -F '"code":0'
test -f /tmp/hec-live/assembly/state
cp /tmp/hec-live/assembly/state /tmp/original-assembly-state
stop_ls
echo LIVE_BEFORE_OK
$L install --local --no-verify /work/@GEM@
$L list --verbose splunk | grep -F 'logstash-input-splunk_hec (@VERSION@)'
/usr/share/logstash/bin/logstash -t -f /tmp/upgrade.conf --path.data /tmp/after 2>&1 | grep 'Configuration OK'
sha256sum -c /tmp/before.sha256
# --- the SAME state directory, now under the new plugin: ids never reused, old traffic stays unacknowledged-unknown, new traffic flows ---
start_ls /tmp/live-after after
test "$(sha256sum /tmp/original-assembly-state | cut -d' ' -f1)" = "$(sha256sum /tmp/hec-live/assembly/backup-v2 | cut -d' ' -f1)"
test -f /tmp/hec-live/assembly/current-v3
post_s2s /tmp/tail.bin | grep -F '"code":0'
post_s2s /tmp/end.bin | grep -F '"code":0'
wait_events 'START migrated'
grep -F 'START migrated\ntrace' /tmp/live-out.ndjson
post_s2s /tmp/head.bin | grep -F '"code":0'
post_s2s /tmp/tail.bin | grep -F '"code":0'
sleep 2
test "$(grep -c 'START migrated' /tmp/live-out.ndjson)" -eq 1
echo ASSEMBLY_MIGRATION_OK
OLD=$(poll_ack "$ACK1"); echo "OLD_ACK_AFTER $OLD"
echo "$OLD" | grep -F "\"$ACK1\":false"
R2=$(post_event '{"event":"upgrade-after"}'); echo "AFTER_RESPONSE $R2"
ACK2=$(echo "$R2" | grep -o '"ackId":[0-9]*' | cut -d: -f2); test -n "$ACK2"
test "$ACK2" -gt "$ACK1"
wait_events upgrade-after
poll_ack "$ACK2" | grep -F "\"$ACK2\":true"
grep -c upgrade-before /tmp/live-out.ndjson | grep -qx 1
stop_ls
echo LIVE_AFTER_OK
/usr/share/logstash/vendor/jruby/bin/jruby -e 'require "rubygems/package"; s=Gem::Package.new("/work/@GEM@").spec; jars=s.files.select{|f| f.end_with?(".jar")}; abort jars.inspect unless jars==["vendor/jars/logstash-input-splunk_hec-@VERSION@.jar"]; puts "ONE_CORRECTLY_NAMED_JAR"'
'''

def main():
    artifact=runtime.artifact_info()
    report={'artifact':artifact,'validators':runtime.validators_info(),'baseline':{'file':BASELINE.name,'sha256':hashlib.sha256(BASELINE.read_bytes()).hexdigest(),'pinned_sha256':BASELINE_SHA256},'runtimes':[],'status':'fail'}
    try:
        assert report['baseline']['sha256']==BASELINE_SHA256,'baseline gem is not the pinned released 0.2.0 artifact'
        script=SCRIPT.replace('@TOKEN@',runtime.TOKEN).replace('@CHANNEL@',runtime.CHANNEL).replace('@BASELINE@',BASELINE.name).replace('@GEM@',runtime.GEM.name).replace('@VERSION@',runtime.VERSION)
        for marker,text,offset in (('@S2S_HEAD@','START migrated',0),('@S2S_TAIL@','trace',14),('@S2S_END@','START next',19)):
            script=script.replace(marker,base64.b64encode(assembly.body(text,offset,source='upgrade-assembly')).decode())
        for role in ('minimum','latest'):
            output=runtime.docker('run','--rm','--entrypoint','bash','-e','JAVA_HOME=/usr/share/logstash/jdk','-v',str(runtime.ROOT)+':/work:ro',runtime.P['logstash.'+role+'.image'],'-c',script,timeout=1800)
            assert 'ONE_CORRECTLY_NAMED_JAR' in output and 'LIVE_BEFORE_OK' in output and 'LIVE_AFTER_OK' in output and 'ASSEMBLY_MIGRATION_OK' in output
            report['runtimes'].append({'role':role,'image':runtime.P['logstash.'+role+'.image'],'status':'pass','output':output})
        assert artifact==runtime.artifact_info();report['status']='pass'
    except Exception as error:
        report['error']={'type':type(error).__name__,'message':str(error),
                         'stdout':getattr(error,'stdout',None),'stderr':getattr(error,'stderr',None)}
    finally:(runtime.EVIDENCE/'upgrade-check.json').write_text(json.dumps(report,indent=2)+'\n')
    if report['status']!='pass':print(json.dumps(report['error'],indent=2),file=sys.stderr)
    return 0 if report['status']=='pass' else 1

if __name__=='__main__':sys.exit(main())
