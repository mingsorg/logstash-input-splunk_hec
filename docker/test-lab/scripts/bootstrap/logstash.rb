# Reference startup for an already-built gem; this does not build a gem or image.
# Check the container's installation, not the old bind-mounted .installed marker:
# that marker cannot prove a newly recreated container contains the plugin.
version = ENV.fetch('PLUGIN_VERSION', '0.1.0') # existing lab baseline, never newest-looking gem
gem = "/work/logstash-input-splunk_hec-#{version}-java.gem"
abort 'provide the explicitly selected plugin gem under /work' unless File.file?(gem)
plugins = IO.popen(['/usr/share/logstash/bin/logstash-plugin', 'list', '--verbose', 'splunk'], &:read)
abort 'could not inspect installed plugins' unless $?.success?
unless plugins.include?("logstash-input-splunk_hec (#{version})")
  abort 'plugin install failed' unless system('/usr/share/logstash/bin/logstash-plugin', 'install', '--local', '--no-verify', gem)
end
exec '/usr/share/logstash/bin/logstash', '--path.settings', '/run-hec/config'
