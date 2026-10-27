Gem::Specification.new do |s|
  s.name = 'logstash-input-splunk_hec'
  s.version = '0.1.0'
  s.platform = 'java'
  s.licenses = ['Apache-2.0']
  s.authors = ['Splunk HEC input contributors']
  s.summary = 'Native-envelope HTTPS HEC input for Logstash 9.5+'
  s.description = 'Receives HEC event, raw and S2S envelopes over verified HTTPS while preserving native payloads for later Logstash transformations.'
  s.required_ruby_version = '>= 3.1'
  s.homepage = 'https://github.com/mingshsg/elastic-ingest-splunk-forwarders'
  s.require_paths = ['lib']
  s.files = Dir['lib/**/*', 'vendor/jars/*.jar', 'README.md', 'LICENSE', 'NOTICE', 'docs/**/*', 'examples/**/*', 'versions.properties'].sort
  s.metadata = { 'logstash_plugin' => 'true', 'logstash_group' => 'input', 'java_plugin' => 'true' }
  s.add_runtime_dependency 'logstash-core-plugin-api', '>= 2.1.16', '< 3.0'
end
