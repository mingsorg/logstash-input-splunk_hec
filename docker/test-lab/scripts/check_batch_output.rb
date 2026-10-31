# Run inside the existing Logstash container, never as the live pipeline itself.
# Sends 100 explicitly labeled synthetic envelopes through the installed HTTP
# output and records actual client calls without recording headers or tokens.
require '/usr/share/logstash/lib/bootstrap/environment'
LogStash::Bundler.setup!({:without => [:build, :development]})
require '/usr/share/logstash/lib/bootstrap/patches/jar_dependencies'
require 'logstash/runner'
require 'logstash/outputs/http'
require 'securerandom'

class BatchRequestObserver
  attr_reader :requests
  def initialize(delegate)
    @delegate = delegate
    @requests = []
  end

  def send(method, url, options)
    events = LogStash::Json.load(options.fetch(:body))
    raise 'expected a JSON array of HEC envelopes' unless events.is_a?(Array)
    allowed = %w[event time host source sourcetype index fields]
    raise 'runtime/local fields leaked into HEC envelopes' unless events.all? { |event| (event.keys - allowed).empty? }
    record = {event_count: events.length, indexes: events.map { |event| event['index'] }.uniq}
    @requests << record
    pending = @delegate.send(method, url, options)
    -> {
      response = pending.call
      record[:http_status] = response.code
      record[:hec_code] = LogStash::Json.load(response.body)['code']
      response
    }
  end

  def close
    @delegate.close
  end
end

probe = SecureRandom.hex(12)
output = LogStash::Outputs::Http.new(
  'url' => 'https://hec-demo-indexer:8088/services/collector/event',
  'http_method' => 'post', 'format' => 'json_batch',
  'headers' => {'Authorization' => 'Splunk ' + ENV.fetch('SPLUNK_HEC_TOKEN')},
  'ssl_enabled' => true, 'ssl_certificate_authorities' => ['/demo/tls/indexer.crt'],
  'connect_timeout' => 10, 'socket_timeout' => 30, 'request_timeout' => 60,
  'retry_failed' => false, 'automatic_retries' => 0)
output.register
observer = BatchRequestObserver.new(output.send(:client))
output.define_singleton_method(:client) { observer }
begin
  events = 100.times.map do |sequence|
    body = {'event' => "http-output-batch-probe #{probe} sequence=#{sequence}",
            'time' => Time.now.to_f.to_s, 'host' => 'http-output-plugin-probe',
            'source' => 'http-output-json-batch-probe', 'sourcetype' => 'hec_batch_probe',
            'index' => 'hec_demo', 'fields' => {'batch_probe' => probe, 'batch_sequence' => sequence}}
    event = LogStash::Event.new(body)
    # Match the clean-envelope boundary in hec-output.conf. No route markers:
    # this is an HTTP-output probe, not evidence of the production ingress path.
    event.to_hash.keys.each { |key| event.remove(key) }
    body.each { |key, value| event.set(key, value) }
    event
  end
  output.multi_receive(events)
  raise "expected one request carrying 100 events: #{observer.requests}" unless
    observer.requests.length == 1 && observer.requests.first[:event_count] == 100 &&
    observer.requests.first[:http_status] == 200 && observer.requests.first[:hec_code] == 0
  puts LogStash::Json.dump(status: 'pass', probe_id: probe,
    http_output_version: Gem.loaded_specs.fetch('logstash-output-http').version.to_s,
    scope: 'installed HTTP output, observed real HTTPS client call; not a live-ingress trace',
    requests: observer.requests)
ensure
  output.close
end
