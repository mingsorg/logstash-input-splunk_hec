# Actual Java Event/PQ serialization plus abrupt-process recovery, not a fake sink.
require 'java'
require 'json'
Dir['/usr/share/logstash/logstash-core/lib/jars/*.jar'].sort.each { |j| require j }
java_import org.logstash.RubyUtil
java_import org.logstash.Event
java_import org.logstash.Timestamp
java_import org.logstash.ackedqueue.SettingsImpl
java_import org.logstash.ackedqueue.ext.JRubyAckedQueueExt
java_import java.time.Instant
java_import com.fasterxml.jackson.databind.ObjectMapper
java_import com.fasterxml.jackson.databind.DeserializationFeature

settings=SettingsImpl.fileSettingsBuilder('/pq/queue').elementClass(Event.java_class)
  .capacity(65536).queueMaxBytes(131072).maxUnread(100)
  .checkpointMaxAcks(1).checkpointMaxWrites(1).build
pq=JRubyAckedQueueExt.create(settings).to_java(JRubyAckedQueueExt)
pq.open
if ARGV[0]=='write'
  nested=java.util.LinkedHashMap.new
  nested.put('message','native')
  nested.put('a.b',java.lang.Long::MAX_VALUE)
  nested.put('decimal',java.lang.Double.new(0.5))
  nested.put('tenth',java.math.BigDecimal.new('0.1'))
  nested.put('precise',java.math.BigDecimal.new('123.45678901234567890123456789'))
  nested.put('unsigned',java.math.BigInteger.new('9223372036854775808'))
  map=java.util.LinkedHashMap.new
  map.put('event',nested)
  map.put('time','1700000000.123456789')
  map.put('@timestamp',Timestamp.new(Instant.parse('2023-11-14T22:13:20.123456789Z')))
  map.put('@metadata',{'splunk_hec'=>{'id'=>'recovery-id'}}.to_java(java.util.Map))
  pq.write(Event.new(map))
  puts 'checkpointed write; halting without queue close'
  $stdout.flush
  java.lang.Runtime.getRuntime.halt(0)
else
  batch=pq.getQueue.readBatch(10,1000)
  raise 'recovery event missing' unless batch && batch.size==1
  event=batch.getElements.get(0).to_java(Event)
  data=JSON.parse(event.toJson)
  mapper=ObjectMapper.new
  mapper.enable(DeserializationFeature::USE_BIG_DECIMAL_FOR_FLOATS)
  exact=mapper.readValue(event.toJson,java.util.Map.java_class).get('event')
  raise 'integer precision lost' unless data['event']['a.b']==9223372036854775807
  raise 'decimal precision lost' unless data['event']['decimal']==0.5
  raise 'decimal tenth lost' unless exact.get('tenth').compareTo(java.math.BigDecimal.new('0.1'))==0
  raise 'arbitrary decimal precision lost' unless exact.get('precise').compareTo(java.math.BigDecimal.new('123.45678901234567890123456789'))==0
  raise 'unsigned integer precision lost' unless exact.get('unsigned').to_s=='9223372036854775808'
  raise 'timestamp precision lost' unless data['@timestamp']=='2023-11-14T22:13:20.123456789Z'
  raise 'source time lost' unless data['time']=='1700000000.123456789'
  raise 'literal dotted key lost' unless data['event'].key?('a.b')
  raise 'metadata ID lost' unless event.getField('[@metadata][splunk_hec][id]').to_s=='recovery-id'
  puts '{"recovered":true,"exact_decimal_roundtrip":true,"unsigned_integer_roundtrip":true,"event":'+event.toJson+',"metadata_id":"recovery-id"}'
  batch.close
  pq.close
end
