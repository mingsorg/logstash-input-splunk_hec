#!/usr/bin/env python3
"""Upgrade the explicit preserved 0.1.0 gem in disposable pinned runtimes only."""
import hashlib
import json
import sys
import runtime

BASELINE=runtime.ROOT/'logstash-input-splunk_hec-0.1.0-java.gem'
BASELINE_SHA256='ee316c417d53f0387890141d2369aeb739421a602e4a4f5e6ffcffe51cdf6b54' # the released 0.1.0 gem; any other file is not the baseline
SCRIPT=r'''
set -e
L=/usr/share/logstash/bin/logstash-plugin
$L install --local --no-verify /work/@BASELINE@
$L list --verbose splunk | grep -F 'logstash-input-splunk_hec (0.1.0)'
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
input { splunk_hec { host => "127.0.0.1" port => 18088 ssl_enabled => false state_directory => "/tmp/hec-live"
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
stop_ls
echo LIVE_BEFORE_OK
$L install --local --no-verify /work/@GEM@
$L list --verbose splunk | grep -F 'logstash-input-splunk_hec (@VERSION@)'
/usr/share/logstash/bin/logstash -t -f /tmp/upgrade.conf --path.data /tmp/after 2>&1 | grep 'Configuration OK'
sha256sum -c /tmp/before.sha256
# --- the SAME state directory, now under the new plugin: ids never reused, old traffic stays unacknowledged-unknown, new traffic flows ---
start_ls /tmp/live-after after
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
        assert report['baseline']['sha256']==BASELINE_SHA256,'baseline gem is not the pinned released 0.1.0 artifact'
        script=SCRIPT.replace('@TOKEN@',runtime.TOKEN).replace('@CHANNEL@',runtime.CHANNEL).replace('@BASELINE@',BASELINE.name).replace('@GEM@',runtime.GEM.name).replace('@VERSION@',runtime.VERSION)
        for role in ('minimum','latest'):
            output=runtime.docker('run','--rm','--entrypoint','bash','-e','JAVA_HOME=/usr/share/logstash/jdk','-v',str(runtime.ROOT)+':/work:ro',runtime.P['logstash.'+role+'.image'],'-c',script,timeout=1800)
            assert 'ONE_CORRECTLY_NAMED_JAR' in output and 'LIVE_BEFORE_OK' in output and 'LIVE_AFTER_OK' in output
            report['runtimes'].append({'role':role,'image':runtime.P['logstash.'+role+'.image'],'status':'pass','output':output})
        assert artifact==runtime.artifact_info();report['status']='pass'
    except Exception as error:
        report['error']={'type':type(error).__name__,'message':str(error),
                         'stdout':getattr(error,'stdout',None),'stderr':getattr(error,'stderr',None)}
    finally:(runtime.EVIDENCE/'upgrade-check.json').write_text(json.dumps(report,indent=2)+'\n')
    if report['status']!='pass':print(json.dumps(report['error'],indent=2),file=sys.stderr)
    return 0 if report['status']=='pass' else 1

if __name__=='__main__':sys.exit(main())
