Gem::Specification.new do |s|
  s.name = 'logstash-input-splunk_hec'
  s.version = '0.1.0'
  s.platform = 'java'
  s.licenses = ['Apache-2.0']
  s.authors = ['Splunk HEC input contributors']
  s.summary = 'Native-envelope HEC and optional S2S TCP input for Logstash 9.5+'
  s.description = 'Receives HEC event, raw and S2S-over-HTTP envelopes over TLS, and optionally classic UF/HF cooked TCP, while preserving native payloads for later Logstash transformations.'
  s.required_ruby_version = '>= 3.1'
  s.homepage = 'https://github.com/mingshsg/elastic-ingest-splunk-forwarders'
  # vendor/jars is a require path so Logstash's Java-plugin registry finds the single plugin jar
  # (it must be named <gem name>-<version>.jar and be the only jar under the require paths).
  s.require_paths = ['lib', 'vendor/jars']
  # The gemspec itself must ship inside the gem: `logstash-plugin install <gem>` unpacks the gem into
  # vendor/local_gems and Logstash discovers the plugin's metadata (logstash_plugin, logstash_group)
  # from that file. Without it the plugin still loads, but `logstash-plugin list` does not show it.
  s.files = Dir['lib/**/*', 'vendor/jars/*.jar', 'README.md', 'LICENSE', 'NOTICE', 'docs/**/*', 'examples/**/*',
                'versions.properties', 'logstash-input-splunk_hec.gemspec'].sort
  s.metadata = { 'logstash_plugin' => 'true', 'logstash_group' => 'input', 'java_plugin' => 'true' }
  s.add_runtime_dependency 'logstash-core-plugin-api', '>= 2.1.16', '< 3.0'
  # Runtime floor enforced at INSTALL time: `logstash-plugin install` fails on Logstash older than 9.5.0
  # instead of installing a plugin that cannot load. (lib/logstash/inputs/splunk_hec.rb also checks at load.)
  s.add_runtime_dependency 'logstash-core', '>= 9.5.0'
end
